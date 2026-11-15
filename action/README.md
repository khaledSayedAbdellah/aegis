# Aegis Mobile Security Audit

A GitHub Action that runs [aegis](https://pub.dev/packages/aegis), an OWASP MASVS security audit for Flutter, React Native, Kotlin Multiplatform and native Android/iOS apps.

* **Code scanning alerts** for every finding, shown in the Security tab and on pull requests.
* **Annotations** on the lines that need fixing.
* **A job summary** with the score, the category scores and the findings.
* **HTML, JSON, SARIF and Markdown reports** as a workflow artifact (PDF on request).
* **Step outputs** (score, grade, counts) for your own checks.

It audits the source (Dart, Kotlin/Java, Swift/Objective-C, manifests, plists, Gradle and Xcode settings, dependencies) and, when you give it one, a release APK, AAB or IPA.

## Usage

```yaml
name: Security

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # code scanning alerts

jobs:
  aegis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: khaledSayedAbdellah/aegis-action@v1
        with:
          profile: l2        # or l1, l1+r, l2+r, banking, fintech...
          fail-on: high      # fail on new high or critical findings
```

The job fails when a new finding reaches `fail-on`, or when the score is below `min-score`. Without these inputs, the values in the project's `aegis.yaml` apply (`aegis init` creates one).

### Audit the release APK too

```yaml
    steps:
      - uses: actions/checkout@v7
      - uses: subosito/flutter-action@v2
        with:
          channel: stable
      - run: flutter build apk --release
      - uses: khaledSayedAbdellah/aegis-action@v1
        with:
          apk: build/app/outputs/flutter-apk/app-release.apk
          profile: l2+r
```

`apk` also takes an AAB (`build/app/outputs/bundle/release/app-release.aab`), and `ipa` takes an IPA. When `path` has no source, only the artifact is audited.

### Accept the current findings

Run `aegis . --update-baseline` once locally and commit `aegis-baseline.json`. The action then only fails on **new** findings; the known ones are still in the reports, marked as known.

### A project in a subfolder

```yaml
      - uses: khaledSayedAbdellah/aegis-action@v1
        with:
          path: apps/mobile
```

Code scanning paths and annotations are made relative to the repository.

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Project folder to audit. |
| `version` | the matching release | aegis version from pub.dev, e.g. `0.12.0`. By default, each action release installs the aegis release it was published with, so `@v1` moves to each new aegis release. Pin `@vX.Y.Z` or `version` to stay on one. |
| `profile` | from `aegis.yaml` | MAS profile: `l1`, `l2`, `l1+r`, `l2+r`, or a preset (`standard`, `sensitive`, `game`, `banking`, `fintech`, `payments`, `government`). |
| `apk` | | Release APK or AAB to audit. |
| `ipa` | | Release IPA to audit. |
| `fail-on` | from `aegis.yaml` | Fail on a new finding at or above `critical`, `high`, `medium` or `low`. |
| `min-score` | from `aegis.yaml` | Fail when the score is below this value. |
| `baseline` | `aegis-baseline.json` | Baseline file of accepted findings. |
| `strict` | `false` | Fail when an applicable check could not complete. |
| `offline` | `false` | Skip the OSV vulnerability lookup of dependencies. |
| `pub-get` | `true` | Run `pub get` when dependencies are not resolved, so the native code of packages can be checked. |
| `lang` | `en` | Report language: `en` or `ar`. |
| `pdf` | `false` | Also write a PDF report. |
| `output-dir` | `aegis-report` | Folder for the reports. |
| `upload-sarif` | `true` | Upload findings to code scanning. |
| `sarif-category` | `aegis` | Code scanning category, to keep several audits of one repository apart. |
| `annotations` | `true` | Annotate new findings (up to 50). |
| `job-summary` | `true` | Show the report in the job summary. |
| `upload-artifact` | `true` | Upload the reports as an artifact. |
| `artifact-name` | `aegis-report` | Name of that artifact. Use a different name for each job in a matrix. |
| `args` | | Other aegis options, e.g. `--ignore-baseline --verbose`. |

## Outputs

| Output | Description |
|---|---|
| `score` | Security score from 0 to 100. |
| `grade` | Letter grade of the score. |
| `exit-code` | `0` passed, `1` a threshold failed, `2` invalid input or an incomplete audit in strict mode. |
| `new-findings` | Findings that are not in the baseline. |
| `critical`, `high`, `medium`, `low` | Failed rules of each severity. |
| `report-dir`, `json-file`, `sarif-file`, `html-file` | Where the reports are. |

To keep the job going after a failure and decide yourself:

```yaml
      - uses: khaledSayedAbdellah/aegis-action@v1
        id: aegis
        continue-on-error: true
      - run: echo "Score ${{ steps.aegis.outputs.score }} (${{ steps.aegis.outputs.grade }})"
```

## Notes

* **Code scanning** needs `security-events: write`. It is free for public repositories; private repositories need GitHub Advanced Security. Without it the upload step fails without failing the job, and the annotations, summary and artifact still work. Set `upload-sarif: false` to skip it.
* **Pull requests from forks** get a read-only token, so their alerts can't be uploaded. The rest of the action works.
* The action uses Dart from the runner when there is one (for example after `subosito/flutter-action`), and installs the stable SDK otherwise.
* It runs on Linux, macOS and Windows runners. iOS code-signature checks of an IPA need a macOS runner.
* aegis checks configuration and code statically. It does not prove an app is secure; see the [aegis documentation](https://github.com/khaledSayedAbdellah/aegis#readme) for what each rule covers.

## Versions

This repository is published from the [`action` folder of aegis](https://github.com/khaledSayedAbdellah/aegis/tree/main/action) with every aegis release: tag `vX.Y.Z` is the action for aegis X.Y.Z, and `v1` follows the latest one. Report issues and send changes to [aegis](https://github.com/khaledSayedAbdellah/aegis).

## License

MIT
