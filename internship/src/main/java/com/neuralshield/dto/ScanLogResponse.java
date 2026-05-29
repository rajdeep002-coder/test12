package com.neuralshield.dto;

import com.neuralshield.model.ThreatLevel;
import java.time.Instant;
import java.util.UUID;

public record ScanLogResponse(
        UUID id,
        UUID userId,
        String url,
        Instant scannedAt,
        ThreatLevel threatLevel,
        String threatType,
        String ipAddress
) {}
