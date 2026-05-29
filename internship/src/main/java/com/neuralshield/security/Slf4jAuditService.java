package com.neuralshield.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

@Service
public class Slf4jAuditService implements AuditService {

    private static final Logger auditLogger = LoggerFactory.getLogger("security-audit");

    @Override
    public void logSecurityEvent(SecurityEvent event, String clientIp, String identifier, String details) {
        String correlationId = MDC.get(CorrelationIdFilter.CORRELATION_ID_LOG_VAR);
        if (correlationId == null) {
            correlationId = "N/A";
        }
        
        auditLogger.info("SECURITY AUDIT | Event: {} | Correlation ID: {} | IP: {} | Identifier: {} | Details: {}",
                event, correlationId, clientIp, identifier, details);
    }
}
