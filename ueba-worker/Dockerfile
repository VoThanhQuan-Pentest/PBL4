# Ubuntu LTS security maintenance avoids deferred util-linux/ncurses/perl
# findings in Debian slim. Keep CPython 3.12, Java 21 and the ML lock unchanged.
FROM eclipse-temurin:21-jre-noble@sha256:35501d3f93173b420ac9001658eb68157e813316b865087e345c187fca422c4c
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends python3.12 python3.12-venv \
    && python3.12 -m venv "$VIRTUAL_ENV" \
    && pip install --disable-pip-version-check --no-cache-dir --only-binary=:all: pip==26.2.2 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --user-group --uid 10001 --create-home ueba
WORKDIR /service
COPY requirements.txt requirements.lock ./
RUN pip install --disable-pip-version-check --no-cache-dir --only-binary=:all: -r requirements.lock
COPY app ./app
USER 10001:10001
EXPOSE 8091
# Preserve the original direct uvicorn entrypoint rather than the JRE CA wrapper.
ENTRYPOINT []
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8091", "--workers", "1"]
