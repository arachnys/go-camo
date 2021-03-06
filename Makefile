APP_VER           := $(shell git describe --always --dirty --tags|sed 's/^v//')
LATEST_COMMIT     := `git rev-parse --short HEAD`
CURRENT_DATE      := `date -u +"%Y-%m-%dT%H:%M:%SZ"`

BUILDDIR          := ${CURDIR}
GOTEST_FLAGS      := -cpu=1,2 -race

TEST_PACKAGES     := `go list ./... | grep -v /vendor/`

define HELP_OUTPUT
Available targets:
  help                this help
  clean               clean up
  clean-vendor        remove vendor sources
  setup               fetch dependencies
  generate            run `go generate`
  test                run tests
  cover               run tests with cover output
  snapshot            creates a release snapshot
  release             release the latest tag
  man                 build all man pages
  all                 run `go generate` and build all man pages
endef
export HELP_OUTPUT

.PHONY: help clean clean-vendor setup generate test cover snapshot release ci-success man all

help:
	@echo "$$HELP_OUTPUT"

clean:
	@rm -rf "${BUILDDIR}/dist/"
	@rm -rf "${BUILDDIR}/man/"*.[1-9]

clean-vendor:
	@rm -rf "${BUILDDIR}/vendor/"

setup:
	@go get -u github.com/golang/dep/cmd/dep
	@go get -u github.com/goreleaser/goreleaser

generate:
	@echo "Running generate..."
	@go generate ./...

test:
	@echo "Running tests..."
	@dep ensure
	@go test ${GOTEST_FLAGS} ${TEST_PACKAGES} -v

cover:
	@echo "Running tests with coverage..."
	@go test -cover ${GOTEST_FLAGS} ${TEST_PACKAGES}

snapshot:
	@echo "Creating release snapshot (no validation or publishing)..."
	@goreleaser --rm-dist --skip-validate --snapshot

release:
	@echo "Releasing (manually)..."
	@goreleaser --rm-dist

ci-success:
	@echo "Building, and releasing..."
	@export BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
	@export VCS_REF=$(git rev-parse --short HEAD)
	@docker login -u="${DOCKER_USERNAME}" -p="${DOCKER_PASSWORD}"
	@if [ -n "${TRAVIS_TAG}" ]; then \
		make release; \
	else \
		make snapshot; \
	fi
	@if [ "${TRAVIS_PULL_REQUEST}" = "false" ] && [ "${TRAVIS_BRANCH}" = "master" ]; then \
		docker push arachnysdocker/go-camo:latest; \
		docker push arachnysdocker/go-camo-url-tool:latest; \
	fi

${BUILDDIR}/man/%: man/%.mdoc
	@cat $< | sed -E "s#.Os (.*) VERSION#.Os \1 ${APP_VER}#" > $@

man: $(patsubst man/%.mdoc,${BUILDDIR}/man/%,$(wildcard man/*.1.mdoc))

all: generate man
