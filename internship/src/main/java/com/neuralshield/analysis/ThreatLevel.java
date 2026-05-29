package com.neuralshield.analysis;

/**
 * Ordered threat severity levels assigned by individual detectors and the
 * {@link ThreatAnalysisService} orchestrator.
 *
 * <p>Score thresholds are used by {@link #fromScore(double)} to map the
 * aggregated weighted score (0–100) to a human-readable level.</p>
 */
public enum ThreatLevel {

    /** No indicators of compromise found. */
    SAFE(0),

    /** Weak signal — anomaly present but low confidence. */
    LOW(20),

    /** Moderate risk — multiple weak signals or one clear indicator. */
    MEDIUM(40),

    /** High risk — strong phishing or malware indicator. */
    HIGH(60),

    /** Confirmed or near-certain threat. */
    CRITICAL(80);

    private final int scoreThreshold;

    ThreatLevel(int scoreThreshold) {
        this.scoreThreshold = scoreThreshold;
    }

    public int getScoreThreshold() {
        return scoreThreshold;
    }

    /**
     * Maps an aggregated score in the range [0, 100] to a {@link ThreatLevel}.
     *
     * @param score weighted aggregate score from the analysis orchestrator
     * @return the corresponding threat level
     */
    public static ThreatLevel fromScore(double score) {
        if (score >= 80) return CRITICAL;
        if (score >= 60) return HIGH;
        if (score >= 40) return MEDIUM;
        if (score >= 20) return LOW;
        return SAFE;
    }
}
