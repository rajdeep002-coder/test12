package com.neuralshield.security;

import com.neuralshield.config.NeuralShieldProperties;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class InMemoryRateLimitService implements RateLimitService {

    private final NeuralShieldProperties properties;
    private final Map<String, Bucket> cache = new ConcurrentHashMap<>();

    public InMemoryRateLimitService(NeuralShieldProperties properties) {
        this.properties = properties;
    }

    @Override
    public Bucket resolveBucket(String ipAddress) {
        return cache.computeIfAbsent(ipAddress, this::newBucket);
    }

    private Bucket newBucket(String ipAddress) {
        int capacity = properties.rateLimit().capacity();
        int refillPerMinute = properties.rateLimit().refillPerMinute();

        return Bucket.builder()
                .addLimit(Bandwidth.classic(capacity, Refill.intervally(refillPerMinute, Duration.ofMinutes(1))))
                .build();
    }
}
