# Use uppercase for AS to match common conventions
FROM golang:1.17 AS build

WORKDIR /build

# Copy go.mod and go.sum
COPY go.* .

# Download module dependencies
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the Go application
RUN go build -o app main.go

# Use a minimal base image for the final stage
FROM debian:11-slim

# Update package lists and install iptables
RUN apt-get update && apt-get install -y iptables

# Copy the built application from the build stage
COPY --from=build /build/app .

# Set the default command to execute the application
CMD ["./app"]