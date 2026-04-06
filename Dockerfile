FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /ccproxy ./cmd/ccproxy

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /ccproxy /ccproxy
EXPOSE 8080
ENTRYPOINT ["/ccproxy"]
