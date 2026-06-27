.PHONY: bootstrap-check bootstrap-strict bootstrap-lock bootstrap-update-baseline

bootstrap-check:
	bash scripts/bootstrap-check.sh

bootstrap-strict:
	bash scripts/bootstrap-check.sh --strict

bootstrap-lock:
	bash scripts/bootstrap-check.sh --strict --lock

bootstrap-update-baseline:
	bash scripts/bootstrap-check.sh --strict --update-baseline
