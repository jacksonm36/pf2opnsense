FROM node:20-alpine AS ui
WORKDIR /ui
COPY web/ui/package.json web/ui/package-lock.json ./
RUN npm ci
COPY web/ui ./
RUN npm run build

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web/embed.go ./web/embed.go
COPY --from=ui /static ./web/static
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /pf2opn ./cmd/pf2opn

FROM alpine:3.21
RUN adduser -D -H -u 65532 pf2opn
COPY --from=build /pf2opn /usr/local/bin/pf2opn
USER pf2opn
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["pf2opn", "serve", "-listen", ":8080"]
