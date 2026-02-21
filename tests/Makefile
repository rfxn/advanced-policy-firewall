.PHONY: test test-verbose \
       test-centos6 test-centos7 test-rocky8 test-rocky9 test-rocky10 \
       test-ubuntu1204 test-ubuntu2004 test-ubuntu2204 test-ubuntu2404 \
       test-all test-modern test-legacy test-deep-legacy \
       test-modern-parallel test-legacy-parallel test-deep-legacy-parallel test-all-parallel

PARALLEL_JOBS := $(shell echo $$(( $$(nproc) * 2 )) | awk '{ print ($$1 < 1) ? 1 : $$1 }')

# Default: Debian 12
test:
	./run-tests.sh

test-verbose:
	./run-tests.sh --formatter pretty

# Individual OS targets (matches CI matrix)
test-centos7:
	./run-tests.sh --os centos7

test-rocky8:
	./run-tests.sh --os rocky8

test-rocky9:
	./run-tests.sh --os rocky9

# Rocky 10 — not in CI matrix (pending stable image), manual only
test-rocky10:
	./run-tests.sh --os rocky10

test-ubuntu2004:
	./run-tests.sh --os ubuntu2004

test-ubuntu2204:
	./run-tests.sh --os ubuntu2204

test-ubuntu2404:
	./run-tests.sh --os ubuntu2404

# Deep legacy OS targets (EOL, in CI matrix)
test-centos6:
	./run-tests.sh --os centos6

test-ubuntu1204:
	./run-tests.sh --os ubuntu1204

# Modern OS targets (active support) — sequential
test-modern:
	./run-tests.sh --os debian12
	./run-tests.sh --os rocky9
	./run-tests.sh --os ubuntu2204
	./run-tests.sh --os ubuntu2404

# Legacy OS targets (EOL but still in production) — sequential
test-legacy:
	./run-tests.sh --os centos7
	./run-tests.sh --os rocky8
	./run-tests.sh --os ubuntu2004

# Deep legacy OS targets (very old EOL, vault/old-releases repos) — sequential
test-deep-legacy:
	./run-tests.sh --os centos6
	./run-tests.sh --os ubuntu1204

# Full matrix (all CI targets) — sequential
test-all:
	./run-tests.sh --os debian12
	./run-tests.sh --os centos6
	./run-tests.sh --os centos7
	./run-tests.sh --os rocky8
	./run-tests.sh --os rocky9
	./run-tests.sh --os ubuntu1204
	./run-tests.sh --os ubuntu2004
	./run-tests.sh --os ubuntu2204
	./run-tests.sh --os ubuntu2404

# Parallel targets — run multiple OS tests concurrently (2× available cores)
test-modern-parallel:
	printf '%s\n' debian12 rocky9 ubuntu2204 ubuntu2404 | \
	  xargs -P $(PARALLEL_JOBS) -I{} ./run-tests.sh --os {}

test-legacy-parallel:
	printf '%s\n' centos7 rocky8 ubuntu2004 | \
	  xargs -P $(PARALLEL_JOBS) -I{} ./run-tests.sh --os {}

test-deep-legacy-parallel:
	printf '%s\n' centos6 ubuntu1204 | \
	  xargs -P $(PARALLEL_JOBS) -I{} ./run-tests.sh --os {}

test-all-parallel:
	printf '%s\n' debian12 centos6 centos7 rocky8 rocky9 ubuntu1204 ubuntu2004 ubuntu2204 ubuntu2404 | \
	  xargs -P $(PARALLEL_JOBS) -I{} ./run-tests.sh --os {}
