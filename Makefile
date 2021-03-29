# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GOBIN_PATH=$(abspath .)/build/bin
ADMIN_SERVER ?=:8090
LOG_ID       ?=
LOG_ENDPOINT ?=$(ADMIN_SERVER)
API_HOST     ?=:7777
KMS_ENDPOINT ?=http://witness.ledger.kms:7878
KID     	 ?=LQ1AflmLXKvTegeb1ihVAUu2V435nKUFkEtXVhaX68Q
KEY_TYPE	 ?=ECDSAP256IEEEP1363
DSN 		 ?=mysql://root@tcp(witness.ledger.mysql:3306)/test

.PHONY: createtree
createtree: export GOBIN=$(GOBIN_PATH)
createtree:
	@echo "Creating tree for witness-ledger"
	@go install github.com/google/trillian/cmd/createtree@v1.3.13
	@$(eval LOG_ID=$(shell $(GOBIN_PATH)/createtree --admin_server=$(ADMIN_SERVER)))
	@echo "Your log id is $(LOG_ID)"

.PHONY: lint
lint: export GOBIN=$(GOBIN_PATH)
lint:
	@echo "Creating tree for witness-ledger"
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GOBIN_PATH)/golangci-lint run

.PHONY: witness-ledger
witness-ledger:
	@echo "Building witness-ledger"
	@go build -o build/bin/witness-ledger cmd/witness-ledger/main.go

.PHONY: witness-ledger-remotekms-demo
witness-ledger-remotekms-demo: witness-ledger createtree
	@$(eval KMS_STORE_ENDPOINT=$(shell curl --request POST '${KMS_ENDPOINT}/kms/keystores' -s -D - --data-raw '{"controller":"controller"}' | grep Location | sed -r 's/Location: //'))
	@$(eval KID=$(shell curl --request POST $(KMS_STORE_ENDPOINT)/keys -s -D - --data-raw '{"keyType":"${KEY_TYPE}"}' | grep Location | sed -r 's/Location: $(shell echo $(KMS_STORE_ENDPOINT)/keys/ | sed -r 's/\//\\\//g')//'))
	@echo "Starting witness-ledger with:"
	@echo "  Log $(LOG_ID)"
	@echo "  KMS $(KMS_STORE_ENDPOINT)"
	@echo "  KID $(KID)"
	@WL_LOG_ID=$(LOG_ID) WL_LOG_ENDPOINT=$(LOG_ENDPOINT) WL_API_HOST=$(API_HOST) WL_KMS_STORE_ENDPOINT=$(KMS_STORE_ENDPOINT) \
  	WL_KEY_ID=$(KID) WL_KEY_TYPE=$(KEY_TYPE) ./build/bin/witness-ledger start

.PHONY: witness-ledger-localkms-demo
witness-ledger-localkms-demo: witness-ledger createtree
	@echo "Starting witness-ledger with log id $(LOG_ID)"
	@WL_LOG_ID=$(LOG_ID) WL_KEY_ID=$(KID) WL_LOG_ENDPOINT=$(LOG_ENDPOINT) WL_API_HOST=$(API_HOST) WL_DSN="$(DSN)" ./build/bin/witness-ledger start