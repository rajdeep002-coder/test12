package com.neuralshield.analysis.detector;

import com.neuralshield.analysis.DetectionResult;

/**
 * Strategy interface for URL threat detection.
 *
 * <p>Every detector is a Spring {@code @Component} bean. The
 * {@link com.neuralshield.analysis.ThreatAnalysisService} collects all
 * implementations via {@code List<ThreatDetector>} injection — no
 * registration code required.</p>
 *
 * <h3>Contract</h3>
 * <ul>
 *   <li>{@link #analyze} must never return {@code null}.</li>
 *   <li>{@link #analyze} must never throw — catch internally and return
 *       {@link DetectionResult#safe}. The orchestrator wraps calls in
 *       {@code safeAnalyze()} as a second safety net.</li>
 *   <li>{@link #getName} must return a stable, human-readable identifier
 *       (used in logs and API responses).</li>
 * </ul>
 */
public interface ThreatDetector {

    /**
     * Analyse a single URL and return a detection result.
     *
     * @param url the raw URL string to inspect (never {@code null} or blank)
     * @return a non-null {@link DetectionResult}
     */
    DetectionResult analyze(String url);

    /**
     * @return a stable, human-readable name for this detector
     *         (e.g. "TyposquattingDetector", "EntropyDetector")
     */
    String getName();
}
