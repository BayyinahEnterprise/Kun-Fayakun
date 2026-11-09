# Bismillah ir-Rahman ir-Rahim

# Reproducibility Notes

## Standalone vs. Monorepo Package Differences

The 18 shared implementation modules (finding.py, config.py, formatters.py,
runner.py, ring_close.py, marad.py, trust_boundary.py, scan_incomplete.py,
secrets.py, injection.py, crypto.py, and 7 adapter modules) are
byte-identical between the monorepo and standalone after normalizing
`kun_fayakun.furqan.checks` imports to `furqan_lint`.

The following files differ intentionally:

- `furqan-lint/src/furqan_lint/__init__.py` -- standalone public API with
  `__version__ = "2.1.0"` and `__all__` exports. The monorepo `__init__.py`
  re-exports check functions instead.
- `furqan-lint/src/furqan_lint/cli.py` -- standalone CLI entry point
  (`furqan-lint` command). Does not exist in monorepo (the monorepo uses
  `kun furqan lint` via a different dispatcher).

## Test Environment

Required dependencies for running the 183 tests:

```
pip install tree-sitter tree-sitter-c tree-sitter-cpp tree-sitter-java tree-sitter-c-sharp tree-sitter-ada pytest
```

From the monorepo root:
```
PYTHONPATH=src pytest tests/furqan/ -v
```

From the standalone package:
```
pip install -e .
pytest tests/furqan/ -v   # tests not shipped in standalone; copy from monorepo
```

## Benchmark Replay

To reconstruct the CSV from archived JSON without scanning:
```
python paper/benchmark.py --from-json paper/ --out-dir /tmp/replay
```

To run a fresh scan:
```
python paper/benchmark.py --scan /path/to/site-packages --monorepo-src src --out-dir paper/
```

## Package Versions

See `versions.json` for the exact Python, bandit, and per-package versions
used in the benchmark run.

# Bismillah ir-Rahman ir-Rahim
