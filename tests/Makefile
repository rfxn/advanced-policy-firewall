BATSMAN_OS_MODERN := debian12 rocky9 ubuntu2404
BATSMAN_OS_LEGACY := centos7 rocky8 ubuntu2004
BATSMAN_OS_DEEP   := centos6 ubuntu1204
BATSMAN_OS_EXTRA  := rocky10
BATSMAN_OS_ALL    := $(BATSMAN_OS_MODERN) $(BATSMAN_OS_LEGACY) $(BATSMAN_OS_DEEP) $(BATSMAN_OS_EXTRA)
BATSMAN_RUN_TESTS := ./run-tests.sh
BATSMAN_PROJECT   := apf

include infra/include/Makefile.tests

# ---------------------------------------------------------------------------
# Override sequential tier targets to continue on failure (report at end)
# ---------------------------------------------------------------------------
# The batsman defaults use || exit 1 which stops on first failure.
# For CI visibility we want all targets to run and report a combined exit.

test-modern:
	@rc=0; for os in $(BATSMAN_OS_MODERN); do $(BATSMAN_RUN_TESTS) --os $$os --parallel || rc=1; done; exit $$rc

test-legacy:
	@rc=0; for os in $(BATSMAN_OS_LEGACY); do $(BATSMAN_RUN_TESTS) --os $$os --parallel || rc=1; done; exit $$rc

test-deep-legacy:
	@if [ -n "$(BATSMAN_OS_DEEP)" ]; then \
		rc=0; for os in $(BATSMAN_OS_DEEP); do $(BATSMAN_RUN_TESTS) --os $$os --parallel || rc=1; done; exit $$rc; \
	fi

test-all:
	@rc=0; for os in $(BATSMAN_OS_ALL); do $(BATSMAN_RUN_TESTS) --os $$os --parallel || rc=1; done; exit $$rc

# ---------------------------------------------------------------------------
# Dev iteration: abort on first failure (local use — not CI)
# ---------------------------------------------------------------------------
test-fast:
	$(BATSMAN_RUN_TESTS) --abort --parallel

# UAT override: --privileged required for iptables access in UAT scenarios
uat:
	BATSMAN_DOCKER_FLAGS="--privileged" $(BATSMAN_RUN_TESTS) -- $(BATSMAN_UAT_PATH)
