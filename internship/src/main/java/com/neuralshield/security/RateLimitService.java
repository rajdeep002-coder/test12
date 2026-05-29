package com.neuralshield.security;

import io.github.bucket4j.Bucket;

public interface RateLimitService {
    Bucket resolveBucket(String ipAddress);
}
