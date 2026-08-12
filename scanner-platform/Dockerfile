FROM golang:1.26-alpine

# Let `go install` auto-download a newer toolchain if a pinned tool version
# ever requires a newer Go than this base image provides (instead of failing
# the build with "requires go >= x.y"). The base image pins 1.26, which
# already satisfies every tool version we pin below.
ENV GOTOOLCHAIN=auto

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

# Pinned exact versions (not @latest) so the image build is reproducible and
# can't silently break when upstream publishes a tag that requires a newer Go
# than the golang:1.24 base image provides.
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.15.0
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.0
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.10.0
RUN go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@v1.3.2

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Build a static worker binary once at image build time instead of
# recompiling with `go run` on every container start.
RUN CGO_ENABLED=0 go build -o /app/scanner-worker ./cmd/worker

CMD ["/app/scanner-worker"]
