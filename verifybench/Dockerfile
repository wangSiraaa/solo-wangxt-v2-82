# ---- frontend build ----
FROM node:20-alpine AS frontend
WORKDIR /fe
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- backend build ----
FROM golang:1.22-alpine AS backend
WORKDIR /src
COPY backend/ ./
RUN CGO_ENABLED=0 go build -o /out/server ./cmd/server

# ---- runtime ----
FROM alpine:3.20
RUN adduser -D -u 10001 app
COPY --from=backend /out/server /app/server
COPY --from=frontend /fe/dist /app/frontend-dist
# Optional external trust root; falls back to the embedded demo root if absent.
COPY backend/internal/demo/demodata/trust-root.json /app/trust-root.json
USER app
EXPOSE 8080
ENTRYPOINT ["/app/server"]
