##################################
# Builder image
##################################
FROM golang:1.12 as builder
RUN mkdir /build
COPY src/ /build/src
ENV GOPATH /build
WORKDIR /build/
RUN go install github.com/IMQS/imqsauth

##################################
# Deployed image
##################################
FROM imqs/ubuntu-base
RUN mkdir -p /etc/imqsbin
RUN mkdir -p /var/log/imqs/
RUN mkdir -p /var/imqs/secrets
COPY --from=builder /build/bin/imqsauth /opt/imqsauth
EXPOSE 80
ENTRYPOINT ["wait-for-nc.sh", "config:80", "--", "wait-for-postgres.sh", "db", "/opt/imqsauth"]
