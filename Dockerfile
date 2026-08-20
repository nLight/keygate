# ── Build frontend ──
FROM oven/bun:1.3.14@sha256:e10577f0db68676a7024391c6e5cb4b879ebd17188ab750cf10024a6d700e5c4 AS frontend
WORKDIR /app/web
COPY web/package.json web/bun.lock* ./
RUN bun install --frozen-lockfile
COPY web/ .
RUN bun run build

# ── Build backend ──
FROM golang:1.25.13-alpine@sha256:1e0126852075c9c60731c8ba49088448b91f63e2aed97ca9d1a9791622a05946 AS backend
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /app/web/dist ./web/dist
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w \
      -X github.com/tabloy/keygate/internal/version.Version=${VERSION} \
      -X github.com/tabloy/keygate/internal/version.Commit=${COMMIT} \
      -X github.com/tabloy/keygate/internal/version.BuildDate=${BUILD_DATE}" \
    -o /keygate ./cmd/server

# ── Runtime ──
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 10001 keygate \
    && adduser -S -D -H -u 10001 -G keygate keygate
WORKDIR /app
COPY --from=backend /keygate /usr/local/bin/keygate
COPY --from=backend /app/db/migrations /app/db/migrations
COPY --from=backend /app/web/dist /app/web/dist
COPY --from=backend /app/docs /app/docs

LABEL org.opencontainers.image.title="Keygate" \
      org.opencontainers.image.description="Open source license management platform" \
      org.opencontainers.image.vendor="Tabloy" \
      org.opencontainers.image.url="https://keygate.app" \
      org.opencontainers.image.source="https://github.com/tabloy/keygate" \
      org.opencontainers.image.licenses="AGPL-3.0"

EXPOSE 9000
ENV PORT=9000
USER 10001:10001
ENTRYPOINT ["keygate"]
