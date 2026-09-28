GO ?= go

.PHONY: deps fmt test vet build run demo smoke check up down

deps:
	$(GO) mod tidy

fmt:
	$(GO) fmt ./...

test:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -o bin/sai-dh ./cmd

run:
	$(GO) run ./cmd -config config.yml

demo:
	$(GO) run ./examples/local

smoke:
	python3 scripts/smoke.py

check: test vet build

up:
	docker compose up --build -d

down:
	docker compose down
