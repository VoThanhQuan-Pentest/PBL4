FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS frontend-build

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10

# Only this variable is substituted in the nginx template. Leaving the rest of
# nginx's $variables untouched is essential for request-time evaluation.
ENV NGINX_TRUSTED_PROXY_CIDR=192.0.2.1/32 \
    NGINX_PUBLIC_SERVER_NAME=localhost \
    NGINX_ENVSUBST_FILTER='NGINX_TRUSTED_PROXY_CIDR|NGINX_PUBLIC_SERVER_NAME'

COPY nginx/nginx.conf /etc/nginx/templates/default.conf.template
COPY nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY nginx/10-validate-trusted-proxy-cidr.sh /docker-entrypoint.d/10-validate-trusted-proxy-cidr.sh
COPY --from=frontend-build /frontend/dist /usr/share/nginx/html

RUN chmod 0555 /docker-entrypoint.d/10-validate-trusted-proxy-cidr.sh
