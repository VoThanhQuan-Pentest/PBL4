FROM maven:3.9.9-eclipse-temurin-21@sha256:3a4ab3276a087bf276f79cae96b1af04f53731bec53fb2e651aca79e4b10211e AS builder
WORKDIR /app

COPY pom.xml .
COPY src ./src
# Resolve the project through Maven's normal dependency mediation. The separate
# go-offline goal traverses lab-only transitive descriptors before mediation and
# can request unavailable Jackson snapshots that are absent from the final tree.
RUN MAVEN_OPTS="-Xmx512m -XX:ActiveProcessorCount=2" mvn -q -DskipTests package

FROM eclipse-temurin:21-jre-jammy@sha256:affcab5356e1270ac35d2361ee83135af2f03e8d580eca78a6d5d6fdbf048db0
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl libbrotli1 \
    # Jammy backport for CVE-2026-111497; fail the build on stale mirrors.
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libbrotli1)" ge 1.0.9-2ubuntu0.1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home appuser

COPY --from=builder /app/target/backend-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8080

USER appuser

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
