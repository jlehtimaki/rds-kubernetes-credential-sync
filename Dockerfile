# Building the drone-kubernetes
FROM --platform=$BUILDPLATFORM golang:1.17-alpine AS builder

ARG BUILDPLATFORM
ARG TARGETARCH

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=$TARGETARCH

WORKDIR /build
COPY . .
RUN go build -o /build/rds-secretsmanager-credential-sync

FROM --platform=$BUILDPLATFORM gcr.io/distroless/base-debian11

ARG BUILDPLATFORM
ARG TARGETARCH
ENV GOARCH=$TARGETARCH

# Copy drone-kubernetes binary
COPY --from=builder /build/rds-secretsmanager-credential-sync /bin/

ENTRYPOINT ["/bin/rds-secretsmanager-credential-sync"]