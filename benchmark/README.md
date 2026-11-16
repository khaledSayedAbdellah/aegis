# Benchmark

Audits public, intentionally vulnerable apps and checks that aegis finds what
each one documents. It is for developing aegis and is not part of the pub
package.

```bash
dart run benchmark/run.dart                 # every app
dart run benchmark/run.dart --app dvma      # one app
dart run benchmark/run.dart --update        # save results.json
```

- `apps.yaml` lists each app, pinned to a commit (source) or to a release
  file and its SHA-256 (binaries), with the rules that must fail and why.
- Downloads go to `~/.cache/aegis-benchmark` (or `AEGIS_BENCHMARK_CACHE`),
  outside the repository, so audits of aegis itself never see them. Nothing
  from the apps is committed; each keeps its own license.
- `results.json` is the last saved run. A rule that failed there and no
  longer fails is a regression; a rule that fails for the first time is
  listed as `new` to review.
- For the OWASP MASTG demos it also counts how many demo folders get at least
  one finding and lists the rest with their titles.

The run exits with code 1 when an expected rule is missed or a regression
shows up.
