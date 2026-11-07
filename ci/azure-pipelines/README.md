# aegis in Azure Pipelines

`aegis-steps.yml` is a steps template: add it to any job that has `dart` on
the PATH and the app checked out.

```yaml
resources:
  repositories:
  - repository: aegis
    type: github
    endpoint: <your GitHub service connection>
    name: khaledSayedAbdellah/aegis
    ref: refs/tags/v0.5.0

steps:
- template: ci/azure-pipelines/aegis-steps.yml@aegis
  parameters:
    projectDir: $(Build.SourcesDirectory)
    aegisSource: git
    aegisGitUrl: https://github.com/khaledSayedAbdellah/aegis.git
    aegisGitRef: v0.5.0
```

Azure Pipelines reads templates from GitHub through a service connection
(Project settings → Service connections → GitHub). Without one, copy
`aegis-steps.yml` into your repository and reference it by path; the template
still installs aegis straight from GitHub.

`example.yml` is a complete pipeline: a source audit on every pull request and
an APK audit on `main`.

## What you get

| Where | What |
|---|---|
| Build summary → **aegis security audit** | The Markdown report: score, new issues, known issues, fixed since the baseline. |
| Build summary → Errors / Warnings | One line per **new** finding, linked to the file and line when it is in the repository. Errors at or above `failOn`, warnings below. |
| Step result | Failed when a new finding reaches `failOn` (or the score is below `minScore`). Orange "succeeded with issues" when there are new findings below it. Green otherwise. |
| Artifact `aegis-report` | `aegis-report.html` (open it in a browser), `.md`, `.json`, `.sarif`. Published even when the step fails. |
| Scans tab (optional, `scansTab: true`) | The SARIF file in the `CodeAnalysisLogs` artifact, shown by Microsoft's free "SARIF SAST Scans Tab" extension. |
| Advanced Security (optional, `advancedSecurity: true`) | Alerts in Repos → Advanced Security, when GitHub Advanced Security for Azure DevOps is enabled. |

## Parameters

| Parameter | Default | |
|---|---|---|
| `projectDir` | `$(Build.SourcesDirectory)` | Folder with `pubspec.yaml`, `aegis.yaml` and `aegis-baseline.json`. |
| `apk` | | Release APK to audit as well. |
| `profile` | from `aegis.yaml` | `l1`, `l2`, `l1+r`, `l2+r` or a preset. |
| `lang` | `en` | `en` or `ar` for the reports. |
| `failOn` | `high` | `critical`, `high`, `medium`, `low`, or `config` to use `fail_on` from `aegis.yaml`. |
| `minScore` | | Fail below this score. Known findings count in the score. |
| `baseline` | `aegis-baseline.json` | Another baseline file. |
| `offline` | `false` | Skip the OSV vulnerability lookup. |
| `aegisSource` | `hosted` | `hosted` (pub.dev), `git` or `path`. |
| `aegisVersion` | latest | For `hosted`, e.g. `^0.5.0`. |
| `aegisGitUrl`, `aegisGitRef` | | For `git`. Pin a tag so a change to aegis can't change your build. |
| `aegisPath` | | For `path`, a checked-out copy (`- checkout: aegis`). |
| `outputDir` | `$(Build.ArtifactStagingDirectory)/aegis` | Absolute path. |
| `artifactName` | `aegis-report` | Must be unique in the run; a re-run job gets `-attempt2`. |
| `scansTab` | `false` | Publish SARIF as `CodeAnalysisLogs` (one job per run). |
| `advancedSecurity` | `false` | Run `AdvancedSecurity-Publish@1`. |
| `continueOnError` | `false` | Report only: the job never fails because of aegis. |

## Notes

* **Private repository.** `dart pub global activate --source git` needs read
  access. For a private GitHub repository give git a token before the
  template, e.g. `git config --global url."https://x-access-token:$(GITHUB_TOKEN)@github.com/".insteadOf "https://github.com/"`
  with `GITHUB_TOKEN` a secret pipeline variable. For a copy in Azure Repos,
  list it in the job's `uses: repositories` and pass `System.AccessToken`
  as an extraheader.
* **Baseline.** Create it once on a laptop with the same options the pipeline
  uses (`--apk`, `--profile`), commit `aegis-baseline.json`, and the pipeline
  only fails on new findings. A source-only run does not report APK findings
  from the baseline as "fixed".
* **Your own packages.** Run `flutter pub get` before the template so aegis
  can find git and path dependencies in `.dart_tool/package_config.json`.
* **AAB.** `apk` also takes an App Bundle, e.g.
  `$(APP_DIR)/build/app/outputs/bundle/prodRelease/app-prod-release.aab`.
  Its certificate is the upload key; see the main README.
