package com.neuralshield.dto;

import com.neuralshield.model.ReportStatus;
import com.neuralshield.model.ThreatLevel;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record ThreatReportResponse(
        UUID id,
        UUID scanLogId,
        ThreatLevel threatLevel,
        String description,
        Map<String, Object> detectorResults,
        ReportStatus status,
        Instant createdAt
) {}
