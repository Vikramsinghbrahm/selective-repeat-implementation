ifneq (,$(wildcard .env))
include .env
export
endif

GO ?= go
BIN_DIR ?= ./bin

ROUTER_HOST ?= 127.0.0.1
ROUTER_PORT ?= 3000
SERVER_HOST ?= 127.0.0.1
SERVER_PORT ?= 8007
DATA_DIR ?= ./examples/data
TIMEOUT ?= 2s
DEADLINE ?= 30s
SESSION_DEADLINE ?= 30s
WINDOW_SIZE ?= 5
MAX_MESSAGE_SIZE ?= 8388608
METRICS_INTERVAL ?= 5s
DROP_RATE ?= 0
MAX_DELAY ?= 0ms
SEED ?= 1

ifeq ($(OS),Windows_NT)
EXE := .exe
endif

.PHONY: build test test-e2e run-router run-server demo-get demo-post clean

build:
	$(GO) build -o $(BIN_DIR)/httpc$(EXE) ./cmd/httpc
	$(GO) build -o $(BIN_DIR)/httpfs$(EXE) ./cmd/httpfs
	$(GO) build -o $(BIN_DIR)/router$(EXE) ./cmd/router

test:
	$(GO) test -buildvcs=false ./...

test-e2e:
	$(GO) test -buildvcs=false ./integration

run-router: build
	$(BIN_DIR)/router$(EXE) --port $(ROUTER_PORT) --drop-rate $(DROP_RATE) --max-delay $(MAX_DELAY) --seed $(SEED)

run-server: build
	$(BIN_DIR)/httpfs$(EXE) -p $(SERVER_PORT) -d $(DATA_DIR) --timeout $(TIMEOUT) --session-deadline $(SESSION_DEADLINE) --metrics-interval $(METRICS_INTERVAL) --window-size $(WINDOW_SIZE) --max-message-size $(MAX_MESSAGE_SIZE) -v

demo-get: build
	$(BIN_DIR)/httpc$(EXE) get --router-host $(ROUTER_HOST) --router-port $(ROUTER_PORT) --server-port $(SERVER_PORT) --timeout $(TIMEOUT) --deadline $(DEADLINE) --window-size $(WINDOW_SIZE) --max-message-size $(MAX_MESSAGE_SIZE) http://$(SERVER_HOST):$(SERVER_PORT)/sample.txt

demo-post: build
	$(BIN_DIR)/httpc$(EXE) post --router-host $(ROUTER_HOST) --router-port $(ROUTER_PORT) --server-port $(SERVER_PORT) --timeout $(TIMEOUT) --deadline $(DEADLINE) --window-size $(WINDOW_SIZE) --max-message-size $(MAX_MESSAGE_SIZE) -f ./examples/data/upload.txt http://$(SERVER_HOST):$(SERVER_PORT)/uploads/posted.txt

clean:
	$(GO) clean -cache -testcache
