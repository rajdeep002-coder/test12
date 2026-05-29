package com.neuralshield.analysis;

/**
 * Immutable result produced by a single {@link com.neuralshield.analysis.detector.UrlDetector}.
 *
 * <p>Use the static factory methods {@link #safe} and {@link #triggered} to construct
 * instances; the canonical constructor is intentionally avoided in call sites.</p>
 *
 * @param detectorName human-readable name of the detector that produced this result
 * @param triggered    {@code true} when the detector found at least one indicator
 * @param severity     threat level assigned by this detector (always {@link ThreatLevel#SAFE}
 *                     when {@code triggered} is {@code false})
 * @param reason       human-readable explanation of the finding, or "No threat detected"
 * @param confidence   detector confidence in [0.0, 1.0]; multiplied by the severity weight
 *                     when computing the aggregated score
 */
public record DetectionResult(
        String detectorName,
        boolean triggered,
        ThreatLevel severity,
        String reason,
        double confidence
) {

    /**
     * Factory for a clean (non-triggering) result.
     *
     * @param detectorName name of the calling detector
     * @return a safe result with full confidence
     */
    public static DetectionResult safe(String detectorName) {
        return new DetectionResult(detectorName, false, ThreatLevel.SAFE, "No threat detected", 1.0);
    }

    /**
     * Factory for a triggered result.
     *
     * @param detectorName name of the calling detector
     * @param severity     assessed severity of the finding
     * @param reason       human-readable description of what was detected
     * @param confidence   detector confidence in [0.0, 1.0]
     * @return a triggered result
     */
    public static DetectionResult triggered(String detectorName,
                                             ThreatLevel severity,
                                             String reason,
                                             double confidence) {
        return new DetectionResult(detectorName, true, severity, reason, confidence);
    }
}
