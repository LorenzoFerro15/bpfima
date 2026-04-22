FROM golang:1.25 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
# Copy the Go Modules manifests
COPY operator/go.mod go.mod
COPY operator/go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the Go source (relies on .dockerignore to filter)
COPY operator/ .

# Build
# the GOARCH has no default value to allow the binary to be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager ./cmd/main.go

FROM fedora:43
RUN sudo dnf -y install libbpf-devel elfutils-libelf-devel zlib-devel clang \
    llvm libyaml-devel pahole bpftool kmod --setopt=install_weak_deps=False

COPY ./ /opt/bpfima
COPY --from=builder /workspace/manager /opt/bpfima-manager
ENTRYPOINT ["/opt/bpfima/scripts/init_module.sh"]
