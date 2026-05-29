package com.neuralshield.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Strongly-typed configuration bound from the neuralshield.* namespace.
 * Validated at startup — missing required env vars fail fast with a clear message.
 */
@Validated
@ConfigurationProperties(prefix = "neuralshield")
public record NeuralShieldProperties(
        Jwt jwt,
        ApiKey apiKey,
        RateLimit rateLimit
) {

    public record Jwt(
            @NotBlank(message = "JWT_SECRET env var must be set")
            String secret,

            @Positive
            long expiryMs
    ) {}

    public record ApiKey(
            @NotBlank(message = "API_KEY env var must be set")
            String value
    ) {}

    public record RateLimit(
            @Min(1) int capacity,
            @Min(1) int refillPerMinute
    ) {}
}
