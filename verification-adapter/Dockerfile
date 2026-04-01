# Multi-stage build: compile a static Go binary, then copy into a minimal
# runtime image. No CGO required — the SQLite driver (modernc.org/sqlite)
# is pure Go.

# --- Build stage ---
FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /adapter .

# --- Runtime stage ---
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app

COPY --from=build /adapter /app/adapter

# Default template and cache directories.
RUN mkdir -p /app/templates /app/cache

EXPOSE 8085

ENV ADAPTER_PORT=8085
ENV CACHE_DB=/app/cache/issuer-cache.db
ENV TEMPLATES_PATH=/app/templates/jsonxt-templates.json

ENTRYPOINT ["/app/adapter"]
