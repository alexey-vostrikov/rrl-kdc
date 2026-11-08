# Everything runs in the image the CI workflow pins. There is no Rust on the
# host on purpose: a toolchain installed outside the one the repository declares
# is a second compiler whose differences nobody sees until CI disagrees.
#
#   make test        # the default configuration
#   make test-all    # every feature: redb backend, secondary crypto cross-check
#   make gates       # what CI runs
#
# The registry lives in a docker volume, the build tree in ./target, so a second
# run does not re-download or re-compile the world.

IMAGE  ?= rust:1.99.1-bookworm
# One wrapper, used by `make` and by hand: two ways to enter the build image is
# two chances for them to diverge, and the one that diverges is always the one
# nobody typed.
CARGO  ?= ./scripts/cargo.sh

.PHONY: help
help:
	@echo "make test        tests in the default configuration"
	@echo "make test-all    tests with every feature"
	@echo "make clippy      clippy over every target, warnings are errors"
	@echo "make fmt         rewrite formatting"
	@echo "make fmt-check   fail if formatting differs"
	@echo "make gates       fmt-check, clippy, test, test-all — what CI runs"
	@echo "make shell       a shell in the build image"

.PHONY: test
test:
	@$(CARGO) test

.PHONY: test-all
test-all:
	@$(CARGO) test --all-features

.PHONY: clippy
clippy:
	@$(CARGO) clippy --all-targets --all-features -- -D warnings

.PHONY: fmt
fmt:
	@$(CARGO) fmt --all

.PHONY: fmt-check
fmt-check:
	@$(CARGO) fmt --all --check

.PHONY: gates
gates: fmt-check clippy test test-all

.PHONY: shell
shell:
	@docker run --rm -it -v "$(shell pwd):/w" -w /w \
	  -u $(shell id -u):$(shell id -g) -e HOME=/tmp $(IMAGE) bash

.PHONY: clean
clean:
	@rm -rf target
