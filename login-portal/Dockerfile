FROM node:20-alpine

# docker-cli lets us `docker exec` into per-site containers to fetch
# CLAUDE.md (and possibly other project files) on demand.
RUN apk add --no-cache tini docker-cli

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY server.js ./
COPY preview-templates/ ./preview-templates/

EXPOSE 3000
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "/app/server.js"]
