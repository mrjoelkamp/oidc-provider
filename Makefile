APP_NAME := oidc-provider

all: build

.PHONY: build
build:
	go build -o bin/$(APP_NAME) main.go

.PHONY: run
run:
	go run main.go

.PHONY: clean
clean:
	rm -rf bin/$(APP_NAME)

.PHONY: test
test:
	go test -v ./...

.PHONY: lint
lint:
	golangci-lint run

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: keys
keys:
	./scripts/keygen.sh

.PHONY: docker-build
docker-build:
	docker build -t $(APP_NAME) .

.PHONY: docker-run
docker-run:
	docker run -p 5001:5001 $(APP_NAME)
