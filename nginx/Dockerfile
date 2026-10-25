FROM node:22.23.4-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS frontend-build

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build

FROM nginx:1.30.6-alpine@sha256:47928bf67eb62a1863cb08d9ecb52d3e704304ba614eaee17884204677702951

# Only this variable is substituted in the nginx template. Leaving the rest of
# nginx's $variables untouched is essential for request-time evaluation.
ENV NGINX_TRUSTED_PROXY_CIDR=192.0.2.1/32 \
    NGINX_PUBLIC_SERVER_NAME=localhost \
    NGINX_ENVSUBST_FILTER='NGINX_TRUSTED_PROXY_CIDR|NGINX_PUBLIC_SERVER_NAME'

COPY nginx/nginx.conf /etc/nginx/templates/default.conf.template
COPY nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY nginx/10-validate-trusted-proxy-cidr.sh /docker-entrypoint.d/10-validate-trusted-proxy-cidr.sh
COPY --from=frontend-build /frontend/dist /usr/share/nginx/html

RUN chmod 0555 /docker-entrypoint.d/10-validate-trusted-proxy-cidr.sh \
    && touch /var/run/nginx.pid \
    && chown -R nginx:nginx /etc/nginx/conf.d /var/cache/nginx /var/log/nginx \
    && chown nginx:nginx /var/run/nginx.pid

# The pinned Alpine image defines nginx as UID/GID 101. Keep the runtime
# identity numeric because AWS bind-mount ownership is necessarily numeric.
USER 101:101
