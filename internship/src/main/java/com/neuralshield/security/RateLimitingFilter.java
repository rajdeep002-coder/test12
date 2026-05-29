package com.neuralshield.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private final RateLimitService rateLimitService;
    private final AuditService auditService;
    private final ObjectMapper objectMapper;

    public RateLimitingFilter(RateLimitService rateLimitService,
                              AuditService auditService,
                              ObjectMapper objectMapper) {
        this.rateLimitService = rateLimitService;
        this.auditService = auditService;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        
        String ip = request.getRemoteAddr();
        
        // Skip rate limiting for static resources / actuator if needed, but standard is rate limit all endpoints
        if (rateLimitService.resolveBucket(ip).tryConsume(1)) {
            filterChain.doFilter(request, response);
        } else {
            auditService.logSecurityEvent(
                    AuditService.SecurityEvent.RATE_LIMIT_VIOLATION,
                    ip,
                    "IPAddress",
                    "Rate limit exceeded on URI: " + request.getRequestURI()
            );

            response.setStatus(429); // HTTP 429 Too Many Requests
            response.setHeader("Retry-After", "60");
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            String correlationId = MDC.get(CorrelationIdFilter.CORRELATION_ID_LOG_VAR);
            if (correlationId == null) {
                correlationId = "N/A";
            }

            Map<String, Object> body = new HashMap<>();
            body.put("timestamp", Instant.now().toString());
            body.put("status", 429);
            body.put("error", "Too Many Requests");
            body.put("message", "API rate limit exceeded. Please try again later.");
            body.put("path", request.getRequestURI());
            body.put("correlationId", correlationId);

            objectMapper.writeValue(response.getOutputStream(), body);
        }
    }
}
