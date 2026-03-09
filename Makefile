# Makefile — eBPF EDR
# Targets: run, test, install, clean

.PHONY: run test test-syscall test-network install clean

# Default Python interpreter (must be available as python3)
PYTHON := python3

# Entry point
AGENT := agent/collector.py

# Attack simulations
SYSCALL_SIM := tests/attack_sim/syscall_sim.py
NETWORK_SIM := tests/attack_sim/exfil_sim.py

# Run the EDR collector (requires root for eBPF)
run:
	sudo $(PYTHON) $(AGENT)

# Run both attack simulations sequentially
# Collector must already be running in another terminal
test: test-syscall test-network

# Run only the syscall simulation (requires root for ptrace)
test-syscall:
	sudo $(PYTHON) $(SYSCALL_SIM)

# Run only the network simulation (no root required)
test-network:
	$(PYTHON) $(NETWORK_SIM)

# Install Python dependencies
install:
	pip install rich pyyaml --break-system-packages

# Remove compiled Python cache files (sudo needed as collector runs as root)
clean:
	sudo find . -type d -name __pycache__ -exec rm -rf {} +
	sudo find . -type f -name "*.pyc" -delete