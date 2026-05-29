package com.neuralshield.security;

public interface AuditService {
    
    enum SecurityEvent {
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        API_KEY_FAILURE,
        RATE_LIMIT_VIOLATION,
        INVALID_JWT_ATTEMPT,
        ACCESS_DENIED
    }

    void logSecurityEvent(SecurityEvent event, String clientIp, String identifier, String details);
}
