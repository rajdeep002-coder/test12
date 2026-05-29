-- V3__create_threat_reports.sql
-- Create threat_reports table for detailed findings on malicious scans

CREATE TABLE threat_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_log_id UUID NOT NULL UNIQUE REFERENCES scan_logs(id) ON DELETE CASCADE,
    threat_level VARCHAR(20) NOT NULL,
    description TEXT NOT NULL,
    detector_results JSONB,
    status VARCHAR(20) NOT NULL DEFAULT 'UNRESOLVED',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Indexes for quick reports filtering and scans correlation
CREATE INDEX idx_threat_reports_threat_level ON threat_reports(threat_level);
CREATE INDEX idx_threat_reports_status ON threat_reports(status);
