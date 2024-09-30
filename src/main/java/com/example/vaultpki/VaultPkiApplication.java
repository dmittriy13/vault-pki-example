package com.example.vaultpki;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.vault.VaultException;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.CertificateBundle;
import org.springframework.vault.support.VaultCertificateRequest;
import org.springframework.vault.support.VaultCertificateResponse;
import org.springframework.web.client.HttpClientErrorException;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.time.Duration;
import java.util.Objects;

/**
 * Vault configuration instructions:
 * <a href="https://developer.hashicorp.com/vault/tutorials/secrets-management/pki-engine?variants=vault-deploy%3Aselfhosted">Build your own certificate authority (CA)</a>
 * <p>
 * JWT understanding help:
 * <a href="https://jwt.io/">JWT.io</a>
 */
@SpringBootApplication
public class VaultPkiApplication {

    public static void main(String[] args) {
        SpringApplication.run(VaultPkiApplication.class, args);
    }

    @Configuration
    public static class VaultConfig {
        @Bean
        public VaultTemplate vaultTemplate() {
            var vaultEndpoint = new VaultEndpoint();
            vaultEndpoint.setScheme("http");

            return new VaultTemplate(vaultEndpoint, new TokenAuthentication("token"));
        }
    }

    @Autowired
    private VaultTemplate vaultTemplate;


    /**
     * 1. подключить билиотеку vault config
     * 2. создать сервис PrivateKeyProvider
     * 2.1 релизовать метод получения private key из vault
     * 3. создать сервис PublicKeyProvider
     * 3.1 реализовать метод получения public key из vault
     * 4. написать unit тесты на методы 2.1 и 3.1
     */
    @EventListener(ApplicationReadyEvent.class)
    public void entrypoint() throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {
        var response = issueCert();
        var privateKey = generatePrivateKey(response);

        // generate jwt
        var certificateBundle = response.getRequiredData();
        var jwt = generateJwt(certificateBundle.getSerialNumber());

        // sign jwt
        var rsassaSigner = new RSASSASigner(privateKey);
        jwt.sign(rsassaSigner);

        // serialize jwt
        var serializedJwt = jwt.serialize();

        // deserialize jwt
        var parsedJwt = SignedJWT.parse(serializedJwt);

        // extract key id
        var kid = parsedJwt.getHeader().getKeyID();

        // verify signature jwt
        var publicKey = getPublicKey(kid);
        RSASSAVerifier rsassaVerifier = new RSASSAVerifier(publicKey);
        boolean verify = parsedJwt.verify(rsassaVerifier);

        System.out.println(verify);
    }

    private PrivateKey generatePrivateKey(VaultCertificateResponse response) throws NoSuchAlgorithmException, InvalidKeySpecException {
        var requiredData = response.getRequiredData();
        var rsa = KeyFactory.getInstance("RSA");
        return rsa.generatePrivate(requiredData.getPrivateKeySpec());
    }

    private VaultCertificateResponse issueCert() {
        var request = VaultCertificateRequest.builder()
                .ttl(Duration.ofHours(1))
                .commonName("111.example.com")
                .build();

        return vaultTemplate.opsForPki("pki_int").issueCertificate("prod", request);
    }

    private RSAPublicKey getPublicKey(String kid) {

        VaultCertificateResponse response;
        try {
            response = vaultTemplate.doWithVault(restOperations ->
                    restOperations.getForObject("pki_int/cert/{kid}", VaultCertificateResponse.class, kid));
        } catch (VaultException e) {
            if (e.getMostSpecificCause() instanceof HttpClientErrorException.NotFound) {
                // if the key is not found, then we will assume that the token has expired
                return null;
            }
            throw e;
        }
        var certificateBundle = Objects.requireNonNull(response).getRequiredData();

        return (RSAPublicKey) certificateBundle.getX509Certificate().getPublicKey();
    }

    private SignedJWT generateJwt(String kid) {
        return new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(),
                new JWTClaimsSet.Builder()
                        .subject("ololo")
                        .build()
        );
    }

}
