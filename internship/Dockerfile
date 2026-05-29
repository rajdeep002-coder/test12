# ─── Stage 1: Build ───────────────────────────────────────────────────────────
FROM eclipse-temurin:25-jdk-alpine AS builder

WORKDIR /build

# Copy dependency descriptors first for layer caching
COPY pom.xml .
COPY .mvn/ .mvn/
COPY mvnw .
RUN chmod +x mvnw

# Download dependencies (cached unless pom.xml changes)
RUN ./mvnw dependency:go-offline -q

# Copy source and build
COPY src/ src/
RUN ./mvnw package -DskipTests -q

# Extract layered jar (Spring Boot 3 layered jars for better layer caching)
RUN java -Djarmode=tools -jar target/neuralshield-*.jar extract --layers --launcher --destination /build/extracted

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM eclipse-temurin:25-jre-alpine AS runtime

# Security: run as non-root
RUN addgroup -S neuralshield && adduser -S neuralshield -G neuralshield

WORKDIR /app

# Copy layered artifacts in cache-friendly order
COPY --from=builder /build/extracted/dependencies/           ./
COPY --from=builder /build/extracted/spring-boot-loader/     ./
COPY --from=builder /build/extracted/snapshot-dependencies/  ./
COPY --from=builder /build/extracted/application/            ./

USER neuralshield

EXPOSE 8080

# Health check — Docker/Compose will mark container healthy before traffic
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD wget -qO- http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", \
    "-XX:+UseContainerSupport", \
    "-XX:MaxRAMPercentage=75.0", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "org.springframework.boot.loader.launch.JarLauncher"]
