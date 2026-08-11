# Build Stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s -X github.com/L9Lenny/caddy-analyzer/cmd.Version=${VERSION}" -o caddy-analyze ./cmd/caddy-analyze

# Production Stage
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk --no-cache add ca-certificates tzdata

RUN addgroup -S caddy && adduser -S -G caddy caddy

WORKDIR /app

COPY --from=builder /app/caddy-analyze /usr/local/bin/caddy-analyze

USER caddy

ENTRYPOINT ["caddy-analyze"]
CMD ["--help"]
