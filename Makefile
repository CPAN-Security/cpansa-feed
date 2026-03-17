IMAGE ?= cpansec-feed-deb

.DEFAULT_GOAL := help

.PHONY: help all deb image test generate setup

all: help

help:
	@printf '%s\n' \
	  'make deb       Build the Debian package in podman' \
	  'make image     Build the Debian 13 podman image' \
	  'make setup     Refresh local input data in podman' \
	  'make generate  Generate the feed in podman' \
	  'make test      Run the test suite in podman'

deb:
	./build-deb.sh $(IMAGE)

image:
	podman build -t $(IMAGE) .

test:
	./podman_run.sh 'prove -l t/metacpan-cache.t t/version-range.t t/cpansa-json.t t/test-cve-compat.t'

generate:
	./podman_run.sh './generate.sh'

setup:
	./podman_run.sh './setup.sh'
