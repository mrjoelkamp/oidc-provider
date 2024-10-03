FROM golang:1.23 AS builder

ENV CGO_ENABLED=0

WORKDIR /app

RUN --mount=type=bind,source=.,target=/app \
    --mount=type=cache,target=$GOPATH/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -o /bin/oidc-provider main.go

FROM gcr.io/distroless/static:nonroot AS dev

COPY --from=builder /bin/oidc-provider /

COPY --chown=nonroot keys/priv.pem ./keys/priv.pem

USER nonroot

ENTRYPOINT [ "/oidc-provider" ]
