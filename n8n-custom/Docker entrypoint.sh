#!/bin/sh
set -e

# lost+found is an ext-filesystem artifact Railway's volume formatting
# creates automatically. It's root-owned by design; n8n never touches
# it, so we skip it rather than fighting a chown we don't need to win.
chown -R node:node /home/node/.n8n 2>/dev/null || true
find /home/node/.n8n -mindepth 1 -maxdepth 1 ! -name lost+found -exec chown -R node:node {} + 2>/dev/null || true

exec su node -c "n8n start"