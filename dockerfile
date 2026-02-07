FROM node:22-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \
  && rm -rf /var/lib/apt/lists/*

ARG DUCKDB_VERSION=1.1.3
RUN curl -L -o /tmp/duckdb.zip https://github.com/duckdb/duckdb/releases/download/v${DUCKDB_VERSION}/duckdb_cli-linux-amd64.zip \
  && unzip /tmp/duckdb.zip -d /usr/local/bin \
  && chmod +x /usr/local/bin/duckdb \
  && rm /tmp/duckdb.zip

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev

COPY server.mjs ./
ENV NODE_ENV=production
EXPOSE 8080
CMD ["npm","run","start"]
