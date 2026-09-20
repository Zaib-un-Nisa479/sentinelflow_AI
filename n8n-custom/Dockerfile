FROM n8nio/n8n:latest

USER root
RUN apk add --no-cache ca-certificates && update-ca-certificates

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]