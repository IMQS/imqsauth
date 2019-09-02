# docker build -t imqs/imqsauth:master --build-arg SSH_KEY="`cat ~/.ssh/id_rsa`" .

##################################
# Builder image
##################################
FROM golang:1.12 as builder

ARG SSH_KEY

# Authorize SSH Host
RUN mkdir -p /root/.ssh && \
    chmod 0700 /root/.ssh && \
    ssh-keyscan github.com > /root/.ssh/known_hosts

# We need this key so that we can read our private IMQS git repos from github
RUN echo "$SSH_KEY" > /root/.ssh/id_rsa && \
    chmod 600 /root/.ssh/id_rsa

RUN git config --global url."git@github.com:".insteadOf "https://github.com/"

RUN mkdir /build
WORKDIR /build

# Cache downloads
COPY go.mod go.sum /build/
RUN go mod download

# Compile
COPY . /build/
RUN go build github.com/IMQS/imqsauth

##################################
# Deployed image
##################################
FROM imqs/ubuntu-base
RUN mkdir -p /etc/imqsbin
RUN mkdir -p /var/log/imqs/
RUN mkdir -p /var/imqs/secrets
COPY --from=builder /build/imqsauth /opt/imqsauth
EXPOSE 80
ENTRYPOINT ["wait-for-nc.sh", "config:80", "--", "wait-for-postgres.sh", "db", "/opt/imqsauth"]
# This is useful for testing
#ENTRYPOINT ["/opt/imqsauth"]
