FROM golang:1.26.1-alpine

RUN apk add --no-cache \
    git \
    gcc \
    g++ \
    musl-dev \
    libpcap-dev \
    make \
    pkgconfig \
    libstdc++

WORKDIR /app

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest

COPY go.mod go.sum ./
RUN go mod download


CMD ["go", "run", "cmd/worker/main.go"]