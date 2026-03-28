# docker build -t imqs/auth:latest --ssh default .

##################################
# Frontend build
##################################
FROM node:20-alpine AS frontend

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# vite.config.ts: outDir: '../httpfront/static' → writes to /httpfront/static
RUN npm run build

##################################
# Builder image
##################################
FROM golang:1.22 AS builder

# Authorize SSH Host
RUN mkdir -p /root/.ssh && \
	chmod 0700 /root/.ssh && \
	ssh-keyscan github.com > /root/.ssh/known_hosts

RUN --mount=type=ssh \
	git config --global url."git@github.com:".insteadOf "https://github.com/"

RUN mkdir /build
WORKDIR /build

# Cache downloads
RUN go env -w GOPRIVATE=github.com/IMQS*
COPY go.mod go.sum /build/
RUN --mount=type=ssh \
	go mod download

# Compile
COPY . /build/
# Overlay the compiled frontend assets (from the Node stage) so that
# the go:embed directive in httpfront/httpfront.go has files to embed.
COPY --from=frontend /httpfront/static /build/httpfront/static
RUN go build imqsauth.go

##################################
# Deployed image
##################################
FROM imqs/ubuntu-base:24.04

RUN mkdir -p /etc/imqsbin
RUN mkdir -p /var/log/imqs/
RUN mkdir -p /var/imqs/secrets
COPY --from=builder /build/imqsauth /opt/imqsauth

EXPOSE 80

HEALTHCHECK CMD curl --fail http://localhost/ping || exit 1

ENTRYPOINT ["wait-for-nc.sh", "config:80", "--", "/opt/imqsauth"]
# This is useful for testing
#ENTRYPOINT ["/opt/imqsauth"]
