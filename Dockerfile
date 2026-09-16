FROM golang:1.24 AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o bff-oidc .

FROM alpine:latest
WORKDIR /app
COPY --from=build /app/bff-oidc ./bff-oidc
COPY --from=build /app/docs ./docs
EXPOSE 5002
CMD ["./bff-oidc"]
