# Makefile for generating cross-platform releases.

VERSION := $(shell git describe --tags)
LDFLAGS := "-X main.gitTag=${VERSION}"
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)
GOARM := $(shell echo ${GOARM})
GOPKG := github.com/namsral/multipass
GOPKG_LIST := $(shell go list ${GOPKG}/... | grep -v /vendor/)
COPY_FILES := README.md CHANGELOG.md LICENSE

ifdef GOARM
PLATFORM := ${GOOS}_${GOARCH}${GOARM}
else
PLATFORM := ${GOOS}_${GOARCH}
endif

release: build/${PLATFORM}/multipass
	cp ${COPY_FILES} build/${PLATFORM}/
	tar -czC build/${PLATFORM} -f build/multipass_${VERSION}_${PLATFORM}.tgz .
	(cd build; shasum -a256 multipass_${VERSION}_${PLATFORM}.tgz > multipass_${VERSION}_${PLATFORM}.sha256)
	#(cd build; gpg --no-default-keyring --armor --output multipass_${VERSION}_${PLATFORM}.tgz.asc --detach-sig multipass_${VERSION}_${PLATFORM}.tgz)

releases:
	#for os in linux darwin windows; do GOOS=$${os} GOARCH=amd64 make release; done
	GOOS=darwin GOARCH=amd64 make release
	GOOS=windows GOARCH=amd64 make release
	GOOS=linux GOARCH=amd64 make release
	GOOS=linux GOARCH=arm GOARM=7 make release
	GOOS=linux GOARCH=arm GOARM=64 make release

build/${PLATFORM}/multipass: build/${PLATFORM}
	go build -ldflags ${LDFLAGS} -o build/${PLATFORM}/multipass ${GOPKG}/cmd/multipass

build/${PLATFORM}:
	mkdir -p build/${PLATFORM}

clean:
	-rm -r build/*

test:
	go test -short ${GOPKG_LIST}

.PHONY: release releases clean test
