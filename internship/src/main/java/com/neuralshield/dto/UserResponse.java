package com.neuralshield.dto;

import com.neuralshield.model.UserRole;
import java.time.Instant;
import java.util.UUID;

public record UserResponse(
        UUID id,
        String username,
        String email,
        UserRole role,
        boolean enabled,
        Instant createdAt,
        Instant updatedAt
) {}
