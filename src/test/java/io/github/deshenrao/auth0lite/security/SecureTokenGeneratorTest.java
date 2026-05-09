package io.github.deshenrao.auth0lite.security;

import io.github.deshenrao.auth0lite.domain.GeneratedToken;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SecureTokenGeneratorTest {

    private final SecureTokenGenerator generator = new SecureTokenGenerator();

    @Test
    void generatesDistinctTokensOnEachCall() {
        GeneratedToken first = generator.generate();
        GeneratedToken second = generator.generate();

        assertThat(first.rawValue()).isNotEqualTo(second.rawValue());
        assertThat(first.hash()).isNotEqualTo(second.hash());
    }

    @Test
    void hashIsDeterministicForTheSameRawValue() {
        GeneratedToken token = generator.generate();

        assertThat(generator.hash(token.rawValue())).isEqualTo(token.hash());
    }

    @Test
    void differentRawValuesProduceDifferentHashes() {
        assertThat(generator.hash("value-one")).isNotEqualTo(generator.hash("value-two"));
    }

    @Test
    void hashIsSixtyFourHexCharactersForSha256() {
        GeneratedToken token = generator.generate();

        assertThat(token.hash()).hasSize(64);
        assertThat(token.hash()).matches("[0-9a-f]{64}");
    }
}
