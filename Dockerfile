FROM golang:1.24 AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /app/bff-oidc ./main.go

FROM alpine:latest
WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata

COPY --from=build /app/bff-oidc /app/bff-oidc
COPY --from=build /app/docs /app/docs
COPY .env /app/.env

EXPOSE 5002
CMD ["./bff-oidc"]
