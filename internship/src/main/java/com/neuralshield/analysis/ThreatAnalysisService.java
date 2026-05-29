package com.neuralshield.analysis;

import com.neuralshield.analysis.detector.ThreatDetector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Central orchestrator for URL threat analysis.
 *
 * <p>Collects all {@link ThreatDetector} beans via Spring DI, runs them
 * against the submitted URL, aggregates the results into a weighted score,
 * and produces an immutable {@link UrlAnalysisResult}.</p>
 *
 * <h3>Extensibility</h3>
 * Adding a new detector requires only creating a new {@code @Component}
 * that implements {@link ThreatDetector}. This service discovers it
 * automatically — <strong>zero modifications needed</strong>.
 *
 * <h3>Fail-Safe Policy</h3>
 * Each detector runs inside {@link #safeAnalyze}. Unchecked exceptions are
 * caught, logged at ERROR level, and replaced with a clean
 * {@link DetectionResult#safe} result. A broken detector never blocks
 * legitimate traffic.
 */
@Service
public class ThreatAnalysisService {

    private static final Logger log = LoggerFactory.getLogger(ThreatAnalysisService.class);

    /**
     * Severity → base weight used in the scoring formula.
     * {@code score = min(100, Σ weight(severity_i) × confidence_i)}
     */
    private static final Map<ThreatLevel, Double> SEVERITY_WEIGHTS = Map.of(
            ThreatLevel.CRITICAL, 80.0,
            ThreatLevel.HIGH,     60.0,
            ThreatLevel.MEDIUM,   35.0,
            ThreatLevel.LOW,      15.0,
            ThreatLevel.SAFE,      0.0
    );

    /** Immutable, ordered snapshot of all registered detectors. */
    private final List<ThreatDetector> detectors;

    /**
     * Spring injects every bean that implements {@link ThreatDetector}.
     * If none are registered the list is empty — the service returns SAFE
     * for all URLs rather than failing.
     *
     * @param detectors all {@link ThreatDetector} beans in the context
     */
    public ThreatAnalysisService(List<ThreatDetector> detectors) {
        this.detectors = Collections.unmodifiableList(new ArrayList<>(detectors));
        log.info("ThreatAnalysisService initialised with {} detector(s): {}",
                this.detectors.size(),
                this.detectors.stream()
                        .map(ThreatDetector::getName)
                        .collect(Collectors.joining(", ")));
    }

    // ────────────────────────────────────────────────────────────────
    //  Public API
    // ────────────────────────────────────────────────────────────────

    /**
     * Analyse a URL for potential threats.
     *
     * @param rawUrl the raw URL string submitted by the user
     * @return an immutable {@link UrlAnalysisResult} containing the
     *         verdict, score, summary, and per-detector breakdown
     */
    public UrlAnalysisResult analyze(String rawUrl) {
        // ── Guard: blank / null URL ──────────────────────────────
        if (rawUrl == null || rawUrl.isBlank()) {
            log.warn("Received null or blank URL for analysis");
            return UrlAnalysisResult.parseFailure(rawUrl == null ? "" : rawUrl,
                    "URL is null or blank");
        }

        String url = rawUrl.trim();

        // ── Guard: basic URL structure ───────────────────────────
        if (!looksLikeUrl(url)) {
            log.warn("URL failed structural pre-check: {}", url);
            return UrlAnalysisResult.parseFailure(url,
                    "Input does not look like a valid URL");
        }

        // ── Run all detectors ────────────────────────────────────
        List<DetectionResult> results = runDetectors(url);

        // ── Aggregate score ──────────────────────────────────────
        double score = computeScore(results);
        ThreatLevel level = ThreatLevel.fromScore(score);
        String summary = buildSummary(results, score, level);

        log.info("Analysis complete — url={} score={} level={} triggered={}",
                url, String.format("%.1f", score), level,
                results.stream().filter(DetectionResult::triggered).count());

        return UrlAnalysisResult.of(url, level, score, summary, results);
    }

    /**
     * @return the number of registered detectors (useful for health checks)
     */
    public int getDetectorCount() {
        return detectors.size();
    }

    /**
     * @return an unmodifiable list of registered detector names
     */
    public List<String> getDetectorNames() {
        return detectors.stream()
                .map(ThreatDetector::getName)
                .toList();
    }

    // ────────────────────────────────────────────────────────────────
    //  Internal
    // ────────────────────────────────────────────────────────────────

    /**
     * Execute every registered detector in order.
     * Each call is wrapped in {@link #safeAnalyze} for isolation.
     */
    private List<DetectionResult> runDetectors(String url) {
        List<DetectionResult> results = new ArrayList<>(detectors.size());
        for (ThreatDetector detector : detectors) {
            results.add(safeAnalyze(detector, url));
        }
        return Collections.unmodifiableList(results);
    }

    /**
     * Fail-safe wrapper. If a detector throws, the exception is logged
     * and a SAFE result is returned so the pipeline continues.
     */
    private DetectionResult safeAnalyze(ThreatDetector detector, String url) {
        try {
            DetectionResult result = detector.analyze(url);
            if (result == null) {
                log.error("Detector [{}] returned null for url={}; treating as SAFE",
                        detector.getName(), url);
                return DetectionResult.safe(detector.getName());
            }
            return result;
        } catch (Exception e) {
            log.error("Detector [{}] threw an exception for url={}: {}",
                    detector.getName(), url, e.getMessage(), e);
            return DetectionResult.safe(detector.getName());
        }
    }

    /**
     * Compute the weighted aggregate score from all triggered results.
     * <pre>score = min(100.0, Σ weight(severity) × confidence)</pre>
     */
    private double computeScore(List<DetectionResult> results) {
        double raw = results.stream()
                .filter(DetectionResult::triggered)
                .mapToDouble(r -> SEVERITY_WEIGHTS.getOrDefault(r.severity(), 0.0) * r.confidence())
                .sum();
        return Math.min(100.0, raw);
    }

    /**
     * Build a human-readable summary string from the analysis results.
     */
    private String buildSummary(List<DetectionResult> results, double score, ThreatLevel level) {
        long triggeredCount = results.stream().filter(DetectionResult::triggered).count();

        if (triggeredCount == 0) {
            return "No threats detected. The URL appears safe.";
        }

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Threat level: %s (score: %.1f/100). ", level, score));
        sb.append(String.format("%d of %d detector(s) triggered. ", triggeredCount, results.size()));

        // Append the reasons from triggered detectors
        String reasons = results.stream()
                .filter(DetectionResult::triggered)
                .map(r -> String.format("[%s] %s (confidence: %.0f%%)",
                        r.detectorName(), r.reason(), r.confidence() * 100))
                .collect(Collectors.joining("; "));
        sb.append("Findings: ").append(reasons).append(".");

        return sb.toString();
    }

    /**
     * Minimal structural check — rejects obviously non-URL input before
     * passing to detectors.  Detectors themselves perform deeper parsing.
     */
    private boolean looksLikeUrl(String url) {
        // Must contain at least one dot or be an IP-based URL
        // Accept http://, https://, and bare domains (e.g., example.com)
        return url.contains(".") || url.matches("https?://\\[?[0-9a-fA-F:]+]?.*");
    }
}
