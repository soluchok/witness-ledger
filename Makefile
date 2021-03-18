# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GOBIN_PATH=$(abspath .)/build/bin
ADMIN_SERVER ?=:8090
LOG_ID       ?=
LOG_ENDPOINT ?=$(ADMIN_SERVER)

.PHONY: createtree
createtree: export GOBIN=$(GOBIN_PATH)
createtree:
	@echo "Creating tree for witness-ledger"
	@go install github.com/google/trillian/cmd/createtree@v1.3.13
	@$(eval LOG_ID=$(shell $(GOBIN_PATH)/createtree --admin_server=$(ADMIN_SERVER)))
	@echo "Your log id is $(LOG_ID)"

.PHONY: witness-ledger
witness-ledger:
	@echo "Building witness-ledger"
	@go build -o build/bin/witness-ledger cmd/witness-ledger/main.go

.PHONY: witness-ledger-demo
witness-ledger-demo: witness-ledger createtree
	@echo "Starting witness-ledger with log id $(LOG_ID)"
	@LOG_ID=$(LOG_ID) LOG_ENDPOINT=$(LOG_ENDPOINT) ./build/bin/witness-ledger