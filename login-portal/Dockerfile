FROM node:20-alpine

RUN apk add --no-cache tini

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY server.js ./
COPY preview-templates/ ./preview-templates/

EXPOSE 3000
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "/app/server.js"]
