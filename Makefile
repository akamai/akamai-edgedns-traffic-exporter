# Copyright 2021 Akamai Techologies, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Ensure that 'all' is the default target
all::

# 1. CONFIGURATION
DOCKER_REPO             ?= akamai
DOCKER_IMAGE_NAME       ?= akamai-edgedns-traffic-exporter
# Add any additional architectures you want to support here
DOCKER_ARCHS            ?= amd64 arm64

# Maintain your specific tool versions
PROMTOOL_VERSION ?= 3.9.1
PROMTOOL         ?= $(FIRST_GOPATH)/bin/promtool
# Note: GO_BUILD_PLATFORM is provided by Makefile.common
PROMTOOL_URL     ?= https://github.com/prometheus/prometheus/releases/download/v$(PROMTOOL_VERSION)/prometheus-$(PROMTOOL_VERSION).$(GO_BUILD_PLATFORM).tar.gz

# 2. INCLUDE SHARED LOGIC
include Makefile.common

# 3. DOCKER OVERRIDES (Using buildx to avoid warnings)
.PHONY: buildx-docker
buildx-docker: $(addprefix buildx-docker-,$(DOCKER_ARCHS))

$(addprefix buildx-docker-,$(DOCKER_ARCHS)): buildx-docker-%:
	@echo ">> building for linux/$* using modern buildx"
	docker buildx build \
		--platform "linux/$*" \
		-t "$(DOCKER_REPO)/$(DOCKER_IMAGE_NAME)-linux-$*:$(SANITIZED_DOCKER_IMAGE_TAG)" \
		-f Dockerfile \
		--build-arg ARCH="$*" \
		--build-arg OS="linux" \
		--load \
		$(DOCKERBUILD_CONTEXT)

# Local convenience target (keeps your original workflow)
.PHONY: docker
docker:
	@echo ">> building docker image for linux/$(GOHOSTARCH) using buildx"
	docker buildx build \
		--platform "linux/$(GOHOSTARCH)" \
		-t "$(DOCKER_REPO)/$(DOCKER_IMAGE_NAME)-linux-$(GOHOSTARCH):$(SANITIZED_DOCKER_IMAGE_TAG)" \
		-f ./Dockerfile \
		--build-arg ARCH=$(GOHOSTARCH) \
		--build-arg OS="linux" \
		--load \
		./

# 4. CUSTOM TARGETS & WRAPPERS
.PHONY: build
build: common-build

.PHONY: all
all:: precheck style check_license lint build

.PHONY: unused
unused: 
	@echo ">> skipping unused check. known Go compiler issue"

.PHONY: promtool
promtool: $(PROMTOOL)

$(PROMTOOL):
	@echo ">> downloading promtool v$(PROMTOOL_VERSION)"
	mkdir -p $(FIRST_GOPATH)/bin
	curl -fsS -L $(PROMTOOL_URL) | tar -xvzf - -C $(FIRST_GOPATH)/bin --no-anchored --strip 1 promtool