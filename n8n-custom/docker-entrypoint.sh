#!/bin/sh
set -e

chown -R node:node /home/node/.n8n 2>/dev/null || true
find /home/node/.n8n -mindepth 1 -maxdepth 1 ! -name lost+found -exec chown -R node:node {} + 2>/dev/null || true

exec su node -c "n8n start"
