.PHONY: test test-verbose \
       test-centos6 test-centos7 test-rocky8 test-rocky9 test-rocky10 \
       test-ubuntu1604 test-ubuntu1804 test-ubuntu2004 test-ubuntu2204 test-ubuntu2404 \
       test-all test-modern test-legacy

# Default: Debian 12
test:
	./tests/run-tests.sh

test-verbose:
	./tests/run-tests.sh --formatter pretty

# Individual OS targets
test-centos6:
	./tests/run-tests.sh --os centos6

test-centos7:
	./tests/run-tests.sh --os centos7

test-rocky8:
	./tests/run-tests.sh --os rocky8

test-rocky9:
	./tests/run-tests.sh --os rocky9

test-rocky10:
	./tests/run-tests.sh --os rocky10

test-ubuntu1604:
	./tests/run-tests.sh --os ubuntu1604

test-ubuntu1804:
	./tests/run-tests.sh --os ubuntu1804

test-ubuntu2004:
	./tests/run-tests.sh --os ubuntu2004

test-ubuntu2204:
	./tests/run-tests.sh --os ubuntu2204

test-ubuntu2404:
	./tests/run-tests.sh --os ubuntu2404

# Modern OS targets (active support)
test-modern:
	./tests/run-tests.sh --os debian12
	./tests/run-tests.sh --os rocky9
	./tests/run-tests.sh --os ubuntu2204
	./tests/run-tests.sh --os ubuntu2404

# Legacy OS targets (EOL but still in production)
test-legacy:
	./tests/run-tests.sh --os centos7
	./tests/run-tests.sh --os rocky8
	./tests/run-tests.sh --os ubuntu1804
	./tests/run-tests.sh --os ubuntu2004

# Full matrix (all supported OS targets)
test-all:
	./tests/run-tests.sh --os debian12
	./tests/run-tests.sh --os centos7
	./tests/run-tests.sh --os rocky8
	./tests/run-tests.sh --os rocky9
	./tests/run-tests.sh --os ubuntu1804
	./tests/run-tests.sh --os ubuntu2004
	./tests/run-tests.sh --os ubuntu2204
	./tests/run-tests.sh --os ubuntu2404
