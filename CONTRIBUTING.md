# Contributing to aegis

Thanks for helping. Bug reports, wrong findings, missed problems and pull requests are all welcome.

## Reporting

* **A vulnerability in aegis itself:** report it privately, see [SECURITY.md](SECURITY.md).
* **A wrong finding or a missed problem:** open a [rule accuracy issue](https://github.com/khaledSayedAbdellah/aegis/issues/new?template=rule_accuracy.yml). A small code snippet or config that reproduces it is the most useful thing you can include. Remove secrets and anything private first.
* **Anything else that doesn't work:** open a [bug report](https://github.com/khaledSayedAbdellah/aegis/issues/new?template=bug_report.yml).

## Setting up

```bash
git clone https://github.com/khaledSayedAbdellah/aegis.git
cd aegis
dart pub get
dart run bin/aegis.dart --version
```

The tests need no network, emulator or Android tools. See [Development](README.md#development-run-from-source-and-run-the-tests) in the README for running single tests and trying your change as the real `aegis` command.

## Before opening a pull request

Run what CI runs:

```bash
dart analyze          # must print "No issues found!"
dart test
```

If you changed `lib/src/security/runtime_driver.py`, also run `python3 test/runtime_driver_test.py -v`.

Then:

* **Add a test.** A new rule needs a test that fires and one that stays quiet on correct code. A fix for a false positive needs a test with the code that used to be flagged.
* **Keep the two report languages in sync.** Text people read in reports lives in `lib/src/l10n/app_en.arb` and `app_ar.arb`. Add every key to both, then regenerate (see [Translation catalogs](README.md#translation-catalogs)). If you can't write the Arabic, put the English text in `app_ar.arb` and say so in the pull request.
* **Update the docs.** New rules go in the [Rules](README.md#rules) table with their MASVS control. New options go in the README.
* **Add a line to `CHANGELOG.md`** under a heading for the next version.

## Adding a rule

Rules live in `lib/src/rules/`, grouped by platform or area, and are registered in `lib/src/rules/registry.dart`. Each rule maps to OWASP MASVS v2, MASWE and CWE where they apply.

A rule should be honest about what it could check. If it could not read what it needed, report the check as incomplete rather than passed. A rule that only sees that something is present, not that it works, should say so in its result.

## Releases

Releases are made by the maintainer from version tags; see **Releasing** in the README.
