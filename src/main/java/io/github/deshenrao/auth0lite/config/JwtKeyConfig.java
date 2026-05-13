package io.github.deshenrao.auth0lite.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtKeyConfig {

    private static final Logger log = LoggerFactory.getLogger(JwtKeyConfig.class);

    @Bean
    public RSAKey jwtSigningKey(JwtKeyProperties properties) throws JOSEException {
        if (properties.isConfigured()) {
            return loadFromPem(properties.privateKeyPem());
        }

        log.warn("app.jwt.key.private-key-pem is not configured -- generating an ephemeral RSA key pair for this "
                + "process. Tokens will not verify after a restart or against another instance of this service. "
                + "Configure a persistent key pair before running more than one instance or in production.");

        return new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyIDFromThumbprint(true)
                .generate();
    }

    private RSAKey loadFromPem(String privateKeyPem) throws JOSEException {
        RSAKey parsed = (RSAKey) JWK.parseFromPEMEncodedObjects(privateKeyPem);
        return new RSAKey.Builder(parsed)
                .keyUse(KeyUse.SIGNATURE)
                .keyIDFromThumbprint()
                .build();
    }
}
