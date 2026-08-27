# syntax=docker/dockerfile:1
FROM golang:1.27-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends llvm-15 clang-15 git make \
	&& rm -rf /var/lib/apt/lists/*
ENV CLANG=clang-15 GOTOOLCHAIN=local
WORKDIR /build/
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
	go mod download
COPY . .
RUN git submodule update --init
RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	make OUTPUT=dae GOFLAGS="-buildvcs=false" CC=clang CGO_ENABLED=0

FROM alpine
RUN mkdir -p /usr/local/share/dae/ /etc/dae/
RUN --mount=type=cache,target=/geo-cache \
	if [ ! -s /geo-cache/geoip.dat ]; then \
		wget -O /geo-cache/geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat; \
	fi && \
	if [ ! -s /geo-cache/geosite.dat ]; then \
		wget -O /geo-cache/geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat; \
	fi && \
	cp /geo-cache/geoip.dat /usr/local/share/dae/geoip.dat && \
	cp /geo-cache/geosite.dat /usr/local/share/dae/geosite.dat
COPY --from=builder /build/dae /usr/local/bin
COPY --from=builder /build/install/empty.dae /etc/dae/config.dae
RUN chmod 0600 /etc/dae/config.dae

CMD ["dae"]
ENTRYPOINT ["dae", "run", "-c", "/etc/dae/config.dae"]
