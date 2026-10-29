FROM node:22.23.4-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS frontend-build

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build

FROM golang:1.26.10-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS diagnostics-build
WORKDIR /src
COPY nginx/diagnostics/ ./
RUN GOMAXPROCS=1 GOGC=40 go test -p 1 ./... \
    && GOMAXPROCS=1 GOGC=40 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/nginx-diagnostics .

FROM nginx:1.30.6-alpine-slim@sha256:dede8895648b461178c3bc604f7eed4423efe5220b2c4d839f5eb3d34ac3f8f7

# Only this variable is substituted in the nginx template. Leaving the rest of
# nginx's $variables untouched is essential for request-time evaluation.
ENV NGINX_TRUSTED_PROXY_CIDR=192.0.2.1/32 \
    NGINX_PUBLIC_SERVER_NAME=localhost \
    NGINX_ENVSUBST_FILTER='NGINX_TRUSTED_PROXY_CIDR|NGINX_PUBLIC_SERVER_NAME'

COPY nginx/nginx.conf /etc/nginx/templates/default.conf.template
COPY nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY nginx/10-validate-trusted-proxy-cidr.sh /docker-entrypoint.d/10-validate-trusted-proxy-cidr.sh
COPY --from=diagnostics-build /out/nginx-diagnostics /usr/local/bin/nginx-diagnostics
COPY --from=frontend-build /frontend/dist /usr/share/nginx/html

RUN chmod 0555 /docker-entrypoint.d/10-validate-trusted-proxy-cidr.sh \
    && sed -i 's@error_log .*;@error_log stderr warn;@' /etc/nginx/nginx.conf \
    && touch /var/run/nginx.pid \
    && chown -R nginx:nginx /etc/nginx/conf.d /var/cache/nginx /var/log/nginx \
    && chown nginx:nginx /var/run/nginx.pid

# The pinned Alpine image defines nginx as UID/GID 101. Keep the runtime
# identity numeric because AWS bind-mount ownership is necessarily numeric.
USER 101:101
ENTRYPOINT ["/usr/local/bin/nginx-diagnostics"]
CMD ["nginx", "-g", "daemon off;"]
