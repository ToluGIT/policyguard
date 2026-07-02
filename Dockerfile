# syntax=docker/dockerfile:1

# ---- build stage ------------------------------------------------------------
# Pinned to the Go toolchain the module targets (go.mod: go 1.21). Using the
# alpine variant keeps the build image small; the final image carries none of it.
FROM golang:1.21-alpine AS build

# No extra build packages needed: the build is pure Go with CGO disabled, and
# version metadata is injected via --build-arg (not VCS stamping), so git is
# unnecessary. Keeping the build stage minimal reduces surface and build time.
WORKDIR /src

# Cache module downloads separately from source so dependency layers are reused
# across source-only changes.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source. The policies/ tree is compiled INTO the binary
# via //go:embed in policies.go, so the final image needs no policy files on disk.
COPY . .

# Version metadata is injected at build time. ARGs default to the committed
# version so a plain `docker build` still produces a coherent binary.
ARG VERSION=0.3.1
ARG COMMIT=docker
ARG DATE=unknown

# CGO disabled => a fully static binary that runs on `scratch`/distroless static.
# -trimpath drops local filesystem paths from the binary (reproducibility +
# avoids leaking the builder's directory layout). -s -w strip debug info.
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
        -o /out/policyguard \
        ./cmd/policyguard

# ---- final stage ------------------------------------------------------------
# distroless static:nonroot has no shell, no package manager, and runs as an
# unprivileged user (uid 65532) by default — a deliberately small attack surface
# for a tool that parses untrusted IaC and loads untrusted Rego. It ships CA
# certificates and /etc/passwd, which is all a static Go CLI needs.
FROM gcr.io/distroless/static-debian12:nonroot

# OCI metadata so `docker inspect` / registries show provenance.
LABEL org.opencontainers.image.title="PolicyGuard" \
      org.opencontainers.image.description="Security policy engine for Terraform/OpenTofu IaC, built on OPA/Rego" \
      org.opencontainers.image.source="https://github.com/ToluGIT/policyguard" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /out/policyguard /usr/local/bin/policyguard

# Already non-root via the base image, but pin it explicitly so a future base
# swap cannot silently regress to root.
USER nonroot:nonroot

# The binary carries its policies embedded, so it works with no mounted policy
# directory. Mount the IaC to scan at /work and point the scan there.
WORKDIR /work

ENTRYPOINT ["policyguard"]
CMD ["--help"]
