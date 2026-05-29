package com.neuralshield.repository;

import com.neuralshield.model.ReportStatus;
import com.neuralshield.model.ThreatLevel;
import com.neuralshield.model.ThreatReport;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface ThreatReportRepository extends JpaRepository<ThreatReport, UUID> {
    
    @EntityGraph(attributePaths = {"scanLog"})
    Optional<ThreatReport> findByScanLogId(UUID scanLogId);

    @EntityGraph(attributePaths = {"scanLog"})
    Page<ThreatReport> findByThreatLevel(ThreatLevel threatLevel, Pageable pageable);

    @EntityGraph(attributePaths = {"scanLog"})
    Page<ThreatReport> findByStatus(ReportStatus status, Pageable pageable);
}
