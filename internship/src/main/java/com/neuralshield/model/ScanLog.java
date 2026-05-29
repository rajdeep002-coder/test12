package com.neuralshield.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "scan_logs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ScanLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @NotBlank(message = "URL is required")
    @Column(nullable = false, columnDefinition = "TEXT")
    private String url;

    @CreationTimestamp
    @Column(name = "scanned_at", nullable = false, updatable = false)
    private Instant scannedAt;

    @NotNull(message = "Threat level is required")
    @Enumerated(EnumType.STRING)
    @Column(name = "threat_level", nullable = false, length = 20)
    private ThreatLevel threatLevel;

    @Column(name = "threat_type", length = 50)
    private String threatType;

    @Size(max = 45)
    @Column(name = "ip_address", length = 45)
    private String ipAddress;
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ScanLog scanLog = (ScanLog) o;
        return id != null && id.equals(scanLog.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
