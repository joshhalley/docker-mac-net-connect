PROJECT         := github.com/joshhalley/docker-mac-net-connect
SETUP_IMAGE     := ghcr.io/joshhalley/docker-mac-net-connect/setup
VERSION         := $(shell git describe --tags 2>/dev/null || echo "v0.0.0")
TAG             := latest-$(VERSION)
LD_FLAGS        := -X ${PROJECT}/version.Version=${VERSION} -X ${PROJECT}/version.SetupImage=${SETUP_IMAGE}:${TAG}

.PHONY: print-vars run build run-go build-go build-docker build-push-docker

print-vars:
        @echo "VERSION: ${VERSION}"
        @echo "TAG: ${TAG}"

run: build-docker run-go
build: build-docker build-go

run-go:
        go run -ldflags "${LD_FLAGS}" ${PROJECT}

build-go:
        go build -ldflags "-s -w ${LD_FLAGS}" ${PROJECT}

build-docker:
        docker build -t ${SETUP_IMAGE}:${TAG} ./client

build-push-docker:
        docker buildx build --platform linux/amd64,linux/arm64 --push -t ${SETUP_IMAGE}:${TAG} ./client