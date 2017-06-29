# Makefile for CTO Go Libraries
#
# Targets:
# - clean       delete all generated files
# - generate    (re)generate all generated files if applicable.
# - test        runs the test (verbose)
# - build       compile executable
#
# - get         get all dependencies (use the $GOPATH/bin/godeps -u $GOPATH/dependencies.tsv)
# - run         run the compiled executable
#
# Meta targets:
# - all is the default target, it runs all the targets in the order above.
#

#CURRENT_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
#PARENT_DIRE := $(notdir $(patsubst %/,%,$(dir $(CURRENT_DIR))))
CURRENT_PACKAGE = $(notdir $(CURDIR))
#CURRENT_PACKAGE = $(notdir $(shell pwd)) 

all: build
	$(info ************  BUILD $(CURRENT_PACKAGE) PACKAGE ************)

run:
	@GODEBUG=gccheckmark=1, go run *.go $(filter-out $@,$(MAKECMDGOALS))

build: format clean test
	@go build ./...

test: get
	@go test -v .

bench: get
	@go test -v -bench . ./...

get:
	@go get -t -v ./...

format:
	@find . -name \*.go -type f -exec gofmt -w {} \;

clean:
	@rm -f $(CURRENT_PACKAGE)
