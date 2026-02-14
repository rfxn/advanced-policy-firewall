.PHONY: test test-verbose

test:
	./tests/run-tests.sh

test-verbose:
	./tests/run-tests.sh --formatter pretty
