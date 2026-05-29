package com.neuralshield.security;

import com.neuralshield.config.NeuralShieldProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;

@Component
public class ApiKeyFilter extends OncePerRequestFilter {

    public static final String API_KEY_HEADER = "X-API-KEY";

    private final NeuralShieldProperties properties;
    private final AuditService auditService;
    private final CustomAuthenticationEntryPoint entryPoint;

    public ApiKeyFilter(NeuralShieldProperties properties,
                        AuditService auditService,
                        CustomAuthenticationEntryPoint entryPoint) {
        this.properties = properties;
        this.auditService = auditService;
        this.entryPoint = entryPoint;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        String requestKey = request.getHeader(API_KEY_HEADER);
        String clientIp = request.getRemoteAddr();

        if (requestKey == null) {
            filterChain.doFilter(request, response);
            return;
        }

        String configuredKey = properties.apiKey().value();

        if (constantTimeEquals(configuredKey, requestKey)) {
            PreAuthenticatedAuthenticationToken auth = new PreAuthenticatedAuthenticationToken(
                    "API_CLIENT",
                    null,
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_ADMIN"))
            );
            SecurityContextHolder.getContext().setAuthentication(auth);
            filterChain.doFilter(request, response);
        } else {
            auditService.logSecurityEvent(
                    AuditService.SecurityEvent.API_KEY_FAILURE,
                    clientIp,
                    "APIKey",
                    "Provided API key was invalid"
            );
            
            entryPoint.commence(request, response, 
                    new org.springframework.security.core.AuthenticationException("Invalid API Key") {});
        }
    }

    /**
     * Constant-time string comparison to prevent timing-based API key enumeration.
     * {@link MessageDigest#isEqual} compares all bytes regardless of mismatch position.
     */
    private boolean constantTimeEquals(String expected, String provided) {
        byte[] a = expected.getBytes(StandardCharsets.UTF_8);
        byte[] b = provided.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(a, b);
    }
}
