# HTTPS MCP server — serves the Bash tool to remote clients (Claude on web /
# mobile / desktop) authenticated by a per-site bearer token.
#
# The container talks to the host's docker daemon (mounted /var/run/docker.sock)
# and `docker exec`s into the per-site container as user `dev`. It can only
# exec into the container named by $MCP_SITE — that's the only docker call it
# knows how to make.

FROM node:20-alpine

RUN apk add --no-cache docker-cli tini

WORKDIR /app
COPY server.js .

EXPOSE 3000
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "/app/server.js"]
