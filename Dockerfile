# Set GO_VERSION to an approved, patched Go release in your deployment pipeline.
ARG GO_VERSION=1.27.1
FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY . .
RUN go mod download && CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o /out/sai-dh ./cmd

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/sai-dh /app/sai-dh
COPY config.yml /app/config.yml
EXPOSE 8083
USER nonroot:nonroot
ENTRYPOINT ["/app/sai-dh"]
