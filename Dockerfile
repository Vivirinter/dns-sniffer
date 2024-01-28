FROM golang:alpine

WORKDIR /app

COPY go.mod go.sum ./

RUN apk add --no-cache libpcap-dev gcc g++ && go mod download

COPY . .

RUN go build -o main .

EXPOSE 9200

CMD ["./main"]