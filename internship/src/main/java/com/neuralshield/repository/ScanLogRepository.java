package com.neuralshield.repository;

import com.neuralshield.model.ScanLog;
import com.neuralshield.model.ThreatLevel;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ScanLogRepository extends JpaRepository<ScanLog, UUID> {
    Page<ScanLog> findByUserId(UUID userId, Pageable pageable);
    Page<ScanLog> findByThreatLevel(ThreatLevel threatLevel, Pageable pageable);
    long countByThreatLevel(ThreatLevel threatLevel);
}
