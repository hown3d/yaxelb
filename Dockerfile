ARG BASE_IMAGE=cgr.dev/chainguard/glibc-dynamic:latest-dev
FROM ${BASE_IMAGE} as base

FROM golang:1.26 as builder
WORKDIR /work
COPY go.mod go.sum ./
RUN --mount=type=cache,dst=/go/pkg/mod \
  go mod download
COPY . .
RUN --mount=type=cache,dst=/root/.cache/go-build \
  --mount=type=cache,dst=/go/pkg/mod \
  CGO_ENABLED=0 GOARCH=${TARGETARCH} GOOS=linux go build -o lb ./cmd

FROM base
COPY --from=builder /work/lb /lb
USER root:root
ENTRYPOINT [ "/lb" ]
