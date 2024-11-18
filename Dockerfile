FROM --platform=$BUILDPLATFORM golang:1.23-bullseye@sha256:45b43371f21ec51276118e6806a22cbb0bca087ddd54c491fdc7149be01035d5 AS builder
RUN apt-get update && apt-get install --yes pkgconf libelf-dev llvm clang
WORKDIR /src
ARG TARGETOS TARGETARCH
COPY . .
RUN make GOOS=$TARGETOS GOARCH=$TARGETARCH

FROM gcr.io/distroless/static-debian12@sha256:ce46866b3a5170db3b49364900fb3168dc0833dfb46c26da5c77f22abb01d8c3
COPY --from=builder /src/daemon /usr/bin/daemon
COPY --from=builder /src/daemon.bpf.o /usr/bin/daemon.bpf.o
WORKDIR /root
ENTRYPOINT ["daemon"]
