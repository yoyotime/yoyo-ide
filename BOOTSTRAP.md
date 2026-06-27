# Bootstrap Workflow

This project currently uses a deterministic pre-bootstrap gate before true stage execution self-hosting.

## Commands

1. Quick check

```bash
bash scripts/bootstrap-check.sh
```

2. Strict report

```bash
bash scripts/bootstrap-check.sh --strict
```

3. Update fixed baseline (only when current state is intentionally accepted)

```bash
bash scripts/bootstrap-check.sh --strict --update-baseline
```

4. Lock mode (CI-style regression gate)

```bash
bash scripts/bootstrap-check.sh --strict --lock
```

## Make Targets

```bash
make bootstrap-check
make bootstrap-strict
make bootstrap-lock
make bootstrap-update-baseline
```

`make bootstrap-lock` is the recommended local pre-push gate.

## CI

GitHub Actions workflow:

- `.github/workflows/bootstrap-gate.yml`

The workflow runs `./scripts/bootstrap-check.sh --strict --lock` on push/PR to `main`.

## Files

- `bootstrap-report.txt`: current run summary
- `bootstrap-report-diff.txt`: comparison against fixed baseline
- `bootstrap-baseline.txt`: fixed baseline used by lock mode

`bootstrap-baseline.txt` should be kept under version control.
`bootstrap-report.txt` and `bootstrap-report-diff.txt` are runtime artifacts and should stay untracked.

## Exit behavior

- `0`: pass
- `1`: determinism check failed (`ky` or `exe` mismatch)
- `2`: invalid argument usage
- `3`: lock mode cannot find baseline
- `4`: lock mode baseline drift detected