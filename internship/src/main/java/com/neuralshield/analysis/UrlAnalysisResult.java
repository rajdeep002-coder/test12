package com.neuralshield.analysis;

import java.time.Instant;
import java.util.List;

/**
 * Aggregated analysis result returned by {@link ThreatAnalysisService}.
 *
 * <p>Contains the final verdict ({@link #overallThreatLevel} and {@link #overallScore}),
 * the per-detector breakdown ({@link #detections}), and a human-readable
 * {@link #summary} for transparency.</p>
 *
 * @param url                the raw URL that was submitted for analysis
 * @param overallThreatLevel final verdict derived from the aggregated score
 * @param overallScore       weighted score in the range [0.0, 100.0]
 * @param summary            human-readable explanation of the analysis outcome
 * @param detections         ordered list of individual detector results (triggered + clean)
 * @param analyzedAt         UTC timestamp of when analysis was completed
 * @param parseError         non-null when the URL could not be parsed; all detectors skipped
 */
public record UrlAnalysisResult(
        String url,
        ThreatLevel overallThreatLevel,
        double overallScore,
        String summary,
        List<DetectionResult> detections,
        Instant analyzedAt,
        String parseError
) {

    /**
     * Factory for a successfully analysed URL (parse error is {@code null}).
     */
    public static UrlAnalysisResult of(String url,
                                       ThreatLevel level,
                                       double score,
                                       String summary,
                                       List<DetectionResult> detections) {
        return new UrlAnalysisResult(url, level, score, summary, detections, Instant.now(), null);
    }

    /**
     * Factory for a URL that failed to parse. The overall level is set to
     * {@link ThreatLevel#HIGH} because an unparseable URL is itself suspicious.
     */
    public static UrlAnalysisResult parseFailure(String url, String reason) {
        DetectionResult parseResult = DetectionResult.triggered(
                "UrlParser", ThreatLevel.HIGH, "URL is malformed: " + reason, 1.0);
        return new UrlAnalysisResult(url, ThreatLevel.HIGH, 60.0,
                "URL could not be parsed: " + reason,
                List.of(parseResult), Instant.now(), reason);
    }

    /** @return {@code true} when the URL was malformed and could not be parsed */
    public boolean hasParseError() {
        return parseError != null;
    }
}
