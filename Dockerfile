# Stage 1: Build dependencies
FROM golang:1.26.1-alpine3.23 AS build_deps

RUN apk add --no-cache git

WORKDIR /workspace

COPY go.mod .
COPY go.sum .

RUN go mod download

# Stage 2: Compile the webhook
FROM build_deps AS build

COPY . .

RUN CGO_ENABLED=0 go build -o dnsexit-webhook -ldflags '-w -extldflags "-static"' .

# Stage 3: Minimal final image
FROM alpine:3.23

# Upgrade all packages to pick up zlib 1.3.2-r0 and future OS patches
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates \
    && addgroup -S appgroup \
    && adduser -S appuser -G appgroup

COPY --from=build /workspace/dnsexit-webhook /usr/local/bin/dnsexit-webhook

USER appuser

ENTRYPOINT ["/usr/local/bin/dnsexit-webhook"]
