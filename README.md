# trustsight-lab

Offline tooling that finds, ranks, and validates deterministic rule
improvements for [TrustSight](https://github.com/emiliano-go/trustsight).

> **Experimental.** This repository is a research workbench. It is not part
> of TrustSight's runtime, it is not a supported product, and its outputs are
> proposals that require human review and the normal TrustSight gates.

## What it does

- **Precision:** finds malicious false positives in a rule's evidence and
  proposes a deterministic guard, normalization, scope, path set, or new
  check. It never changes a weight.
- **Recall:** groups the committed bypass corpus by capability shape and
  joins each group to the rule family the campaign expected.
- **Validation:** applies a candidate to a throwaway worktree and measures it
  with the TrustSight harness and calibration gates.

The lab is offline. Nothing learned here runs inside the scorer, so the
shipped result stays deterministic and reproducible.

## Quick start

The two sibling checkouts must exist next to this repository: `trustsight`
and `trustsight-harness`.

```bash
uv run python -m lab.cli pins --out config/pins.json
uv run python -m lab.cli corpora
uv run python -m lab.cli labels
uv run python -m lab.cli mine --out reports/predicates.json
uv run python -m lab.cli gaps --out reports/gaps.json
uv run python -m lab.cli report
uv run pytest
```

Candidates are rendered as patch files and validated in a worktree:

```bash
uv run python -m lab.cli candidates
uv run python -m lab.cli validate \
  --candidate reports/candidates/C024-phantom-install.json --tier 1
```

The watcher database is read-only. A bounded sample can be extracted from a
container, and a full snapshot can be pulled and resumed:

```bash
uv run python -m lab.cli snapshot --host contabo --container trustsight-watch
uv run python -m lab.cli extract --db data/watcher.db --out data/watcher
```

## Layout

```
lab/pins.py             pinned TrustSight and harness revisions
lab/ingest/             reports, corpora, watcher snapshot and extraction
lab/features/           evidence recomputation and finding rows
lab/labels/             hard, benign, bypass, and contradiction labels
lab/models/             predicate miner, FP ranker, gap clusterer
lab/candidates/         deterministic fix templates
lab/validate/           worktree runner and acceptance metrics
```

## Labels

- `hard_fp`: an adjudicated false positive at confidence 0.9 or higher.
  This is the only precision target.
- `tp_benign`: a real finding on a benign practice. It stays in the report
  and must keep firing. It is never a negative.
- `tp`: malicious fixtures, detected harness traces, and IOC entries.
- `bypass`: committed harness bypasses.
- Contradiction labels are weak positives. They are emitted only when the
  recipe snapshot is within six hours of the analysis, so an upstream version
  bump is not mistaken for a rule bug.

## Limits

The FP reports are point in time. Only two of sixteen carry a corpus diff for
`fp_verify`, and some describe behavior already fixed in the pinned build.
Tree-dependent guards cannot be validated through the stateless diff path and
need a full review replay.

## Tests

```bash
uv run --with pytest pytest -q
uv run --with ruff ruff check lab tests
```
