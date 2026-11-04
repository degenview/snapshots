VERSION ?= dev
GO      ?= go

.PHONY: build test cover lint vuln run docker up clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/snapshots ./cmd/snapshots

test:
	$(GO) test -race ./...

cover:
	$(GO) test -race -coverprofile=coverage.out ./... && $(GO) tool cover -func=coverage.out | tail -1

lint:
	golangci-lint run ./...

vuln:
	govulncheck ./...

run:
	LOG_FORMAT=text LISTEN_ADDR=127.0.0.1:8080 SETUP_TOKEN=local-dev-setup-token $(GO) run ./cmd/snapshots

docker:
	docker build --build-arg VERSION=$(VERSION) -t snapshots:local .

up:
	docker compose up --build

clean:
	rm -rf bin dist coverage.out
