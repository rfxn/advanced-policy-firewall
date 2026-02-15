.PHONY: test test-verbose \
       test-centos6 test-centos7 test-rocky8 test-rocky9 test-rocky10 \
       test-ubuntu1604 test-ubuntu1804 test-ubuntu2004 test-ubuntu2204 test-ubuntu2404 \
       test-all test-modern test-legacy \
       test-modern-parallel test-legacy-parallel test-all-parallel

HALF_CORES := $(shell echo $$(( $$(nproc) / 2 )) | awk '{ print ($$1 < 1) ? 1 : $$1 }')

# Default: Debian 12
test:
	./run-tests.sh

test-verbose:
	./run-tests.sh --formatter pretty

# Individual OS targets
test-centos6:
	./run-tests.sh --os centos6

test-centos7:
	./run-tests.sh --os centos7

test-rocky8:
	./run-tests.sh --os rocky8

test-rocky9:
	./run-tests.sh --os rocky9

test-rocky10:
	./run-tests.sh --os rocky10

test-ubuntu1604:
	./run-tests.sh --os ubuntu1604

test-ubuntu1804:
	./run-tests.sh --os ubuntu1804

test-ubuntu2004:
	./run-tests.sh --os ubuntu2004

test-ubuntu2204:
	./run-tests.sh --os ubuntu2204

test-ubuntu2404:
	./run-tests.sh --os ubuntu2404

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
	./run-tests.sh --os ubuntu1804
	./run-tests.sh --os ubuntu2004

# Full matrix (all supported OS targets) — sequential
test-all:
	./run-tests.sh --os debian12
	./run-tests.sh --os centos7
	./run-tests.sh --os rocky8
	./run-tests.sh --os rocky9
	./run-tests.sh --os ubuntu1804
	./run-tests.sh --os ubuntu2004
	./run-tests.sh --os ubuntu2204
	./run-tests.sh --os ubuntu2404

# Parallel targets — run multiple OS tests concurrently
test-modern-parallel:
	printf '%s\n' debian12 rocky9 ubuntu2204 ubuntu2404 | \
	  xargs -P $(HALF_CORES) -I{} ./run-tests.sh --os {}

test-legacy-parallel:
	printf '%s\n' centos7 rocky8 ubuntu1804 ubuntu2004 | \
	  xargs -P $(HALF_CORES) -I{} ./run-tests.sh --os {}

test-all-parallel:
	printf '%s\n' debian12 centos7 rocky8 rocky9 ubuntu1804 ubuntu2004 ubuntu2204 ubuntu2404 | \
	  xargs -P $(HALF_CORES) -I{} ./run-tests.sh --os {}
