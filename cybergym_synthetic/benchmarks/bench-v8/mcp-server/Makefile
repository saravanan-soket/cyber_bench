.PHONY: all build clean test test-functional test-isolation

all: build

# How many functional/isolation tests run concurrently. Each spawns its own
# docker container, so 4 is a sane default for a typical dev box (~few GB
# of d8 grader memory at peak). Override per-invocation if needed:
#   make test-functional IMAGE=cve-2024-4761 PARALLEL=8
PARALLEL ?= 4

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o server ./cmd/server/

clean:
	rm -f server

test:
	go test -v ./grader/

# Functional: capability-correctness tests (does the grader score PoCs right?).
test-functional:
ifndef IMAGE
	$(error IMAGE is required. Usage: make test-functional IMAGE=cve-2024-4761)
endif
	go test -v -tags=functional -timeout 600s -parallel=$(PARALLEL) ./test/ -image=$(IMAGE) $(if $(SERVER),-server=$(SERVER))

# Isolation: reward-hacking / security-property tests (cross-UID boundary,
# MPK toggle, agent-daemon attacks on grader-UID state).  Slower than
# functional because it spawns background pollers around grade() calls.
test-isolation:
ifndef IMAGE
	$(error IMAGE is required. Usage: make test-isolation IMAGE=cve-2024-4761)
endif
	go test -v -tags=isolation -timeout 900s -parallel=$(PARALLEL) ./test/ -image=$(IMAGE) $(if $(SERVER),-server=$(SERVER))
