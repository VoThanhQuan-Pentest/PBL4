FROM golang:1.26.10-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN GOMAXPROCS=1 GOGC=40 go test -p 1 ./...
RUN GOMAXPROCS=1 GOGC=40 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/prevention-gateway .

FROM scratch
COPY --from=build /out/prevention-gateway /prevention-gateway
USER 10001:10001
EXPOSE 8082
ENTRYPOINT ["/prevention-gateway"]
