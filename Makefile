# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build

all: build
build:
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "scopetrack" cmd/scopetrack/main.go
