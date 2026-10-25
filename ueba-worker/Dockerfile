# Keep CPython 3.12 and Java 21 on the same security-maintained OS/ABI.
FROM eclipse-temurin:21-jre-noble@sha256:35501d3f93173b420ac9001658eb68157e813316b865087e345c187fca422c4c AS python-base
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends python3.12 \
    && rm -rf /var/lib/apt/lists/*

FROM python-base AS dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3.12-venv \
    && python3.12 -m venv "$VIRTUAL_ENV" \
    && pip install --disable-pip-version-check --no-cache-dir --only-binary=:all: pip==26.2.2 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /service
COPY requirements.txt requirements.lock ./
# Installers and their vendored dependencies are not needed to serve requests.
# Uninstall via package metadata; retain every locked ML/runtime dependency.
RUN pip install --disable-pip-version-check --no-cache-dir --only-binary=:all: -r requirements.lock \
    && pip check \
    && pip uninstall -y pip

FROM python-base AS runtime
COPY --from=dependencies /opt/venv /opt/venv
RUN useradd --system --user-group --uid 10001 --create-home ueba
WORKDIR /service
COPY requirements.txt requirements.lock ./
COPY app ./app
# Fail the build if an installer or a locked runtime package is missing/wrong.
RUN python -c 'import importlib.metadata as m, importlib.util as u; from pathlib import Path; expected = dict(line.split("==") for line in Path("requirements.lock").read_text().splitlines() if line and not line.startswith("#")); assert u.find_spec("pip") is None; assert all(m.version(name) == version for name, version in expected.items()), "runtime dependency lock mismatch"'
USER 10001:10001
EXPOSE 8091
# Preserve the original direct uvicorn entrypoint rather than the JRE CA wrapper.
ENTRYPOINT []
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8091", "--workers", "1"]
