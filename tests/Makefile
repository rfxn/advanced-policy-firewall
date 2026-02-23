.PHONY: test test-serial test-verbose \
       test-centos6 test-centos7 test-rocky8 test-rocky9 test-rocky10 \
       test-ubuntu1204 test-ubuntu2004 test-ubuntu2404 \
       test-all test-modern test-legacy test-deep-legacy \
       test-modern-parallel test-legacy-parallel test-deep-legacy-parallel test-all-parallel

PARALLEL_JOBS := $(shell echo $$(( $$(nproc) * 2 )) | awk '{ print ($$1 < 1) ? 1 : $$1 }')

# Default: Debian 12 (parallel within-OS)
test:
	./run-tests.sh --parallel

# Sequential: old behavior (single container, all files)
test-serial:
	./run-tests.sh

test-verbose:
	./run-tests.sh --parallel --formatter pretty

# Individual OS targets (parallel within-OS)
test-centos7:
	./run-tests.sh --os centos7 --parallel

test-rocky8:
	./run-tests.sh --os rocky8 --parallel

test-rocky9:
	./run-tests.sh --os rocky9 --parallel

# Rocky 10 — not in CI matrix (pending stable image), manual only
test-rocky10:
	./run-tests.sh --os rocky10 --parallel

test-ubuntu2004:
	./run-tests.sh --os ubuntu2004 --parallel

test-ubuntu2404:
	./run-tests.sh --os ubuntu2404 --parallel

# Deep legacy OS targets (EOL, in CI matrix)
test-centos6:
	./run-tests.sh --os centos6 --parallel

test-ubuntu1204:
	./run-tests.sh --os ubuntu1204 --parallel

# Modern OS targets (active support) — sequential across OS
test-modern:
	./run-tests.sh --os debian12 --parallel
	./run-tests.sh --os rocky9 --parallel
	./run-tests.sh --os ubuntu2404 --parallel

# Legacy OS targets (EOL but still in production) — sequential across OS
test-legacy:
	./run-tests.sh --os centos7 --parallel
	./run-tests.sh --os rocky8 --parallel
	./run-tests.sh --os ubuntu2004 --parallel

# Deep legacy OS targets (very old EOL, vault/old-releases repos) — sequential
test-deep-legacy:
	./run-tests.sh --os centos6 --parallel
	./run-tests.sh --os ubuntu1204 --parallel

# Full matrix (all CI targets) — sequential across OS
test-all:
	./run-tests.sh --os debian12 --parallel
	./run-tests.sh --os centos6 --parallel
	./run-tests.sh --os centos7 --parallel
	./run-tests.sh --os rocky8 --parallel
	./run-tests.sh --os rocky9 --parallel
	./run-tests.sh --os ubuntu1204 --parallel
	./run-tests.sh --os ubuntu2004 --parallel
	./run-tests.sh --os ubuntu2404 --parallel

# Parallel targets — run multiple OS tests concurrently (2x available cores)
test-modern-parallel:
	printf '%s\n' debian12 rocky9 ubuntu2404 | \
	  xargs -P $(PARALLEL_JOBS) -I{} ./run-tests.sh --os {} --parallel

test-legacy-parallel:
	printf '%s\n' centos7 rocky8 ubuntu2004 | \
	  xargs -P $(PARALLEL_JOBS) -I{} ./run-tests.sh --os {} --parallel

test-deep-legacy-parallel:
	printf '%s\n' centos6 ubuntu1204 | \
	  xargs -P $(PARALLEL_JOBS) -I{} ./run-tests.sh --os {} --parallel

test-all-parallel:
	printf '%s\n' debian12 centos6 centos7 rocky8 rocky9 ubuntu1204 ubuntu2004 ubuntu2404 | \
	  xargs -P $(PARALLEL_JOBS) -I{} ./run-tests.sh --os {} --parallel
