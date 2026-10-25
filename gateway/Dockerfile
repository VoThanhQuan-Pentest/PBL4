FROM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS build
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
