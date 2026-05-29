-- V2__create_scan_logs.sql
-- Create scan_logs table for storing URL scanning results

CREATE TABLE scan_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    url TEXT NOT NULL,
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    threat_level VARCHAR(20) NOT NULL,
    threat_type VARCHAR(50),
    ip_address VARCHAR(45)
);

-- Indexes for performance tuning and compliance with requirements
CREATE INDEX idx_scan_logs_user_id ON scan_logs(user_id);
CREATE INDEX idx_scan_logs_scanned_at ON scan_logs(scanned_at);
CREATE INDEX idx_scan_logs_threat_level ON scan_logs(threat_level);
