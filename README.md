# DNS Sniffer

DNS Sniffer is a Go application that listens to and analyzes DNS traffic.

## Installation

```shell
# Clone the repository
git clone https://github.com/Vivirinter/dns-sniffer

# Navigate to the project directory
cd dns-sniffer

# Build the Docker image
docker build -t dns-sniffer .

# Run the Docker container
docker run -p 9200:9200 dns-sniffer
```

## Testing

To run the tests, execute the following command:

```shell
go test ./...
```