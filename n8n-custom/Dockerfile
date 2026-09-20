FROM docker.n8n.io/n8nio/n8n

USER root
RUN apk add --no-cache ca-certificates && update-ca-certificates

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Deliberately NOT switching back to "USER node" here. If we did, the
# container would start as node again, and our entrypoint below would
# never get the chance to run as root to fix the volume's ownership.
# The entrypoint itself drops to node right before starting n8n, so
# n8n's actual runtime process still ends up non-root, same as before —
# we're just deferring that switch until after the one-time permission fix.
ENTRYPOINT ["/docker-entrypoint.sh"]