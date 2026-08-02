FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends logrotate bsdutils \
    && rm -rf /var/lib/apt/lists/*

COPY observability/logrotate/nginx-access /etc/nginx-access
COPY observability/tests/logrotate/fake-docker /usr/bin/docker

RUN chown root:root /etc/nginx-access /usr/bin/docker \
    && chmod 0644 /etc/nginx-access \
    && chmod 0755 /usr/bin/docker

# Fail closed when the image is started outside the regression harness. The
# harness opts into UID 0 only for the exact logrotate operations that must
# create/chown host-compatible log files.
USER 65534:65534

ENTRYPOINT ["/usr/sbin/logrotate"]
