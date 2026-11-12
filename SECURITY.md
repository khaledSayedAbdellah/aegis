# Security policy

Normal bugs and wrong findings go in [public issues](https://github.com/khaledSayedAbdellah/aegis/issues/new/choose), so anyone who hits the same problem can find the answer. Only vulnerabilities in aegis itself are reported privately, and only until a fix is released: an attacker could use a published vulnerability against everyone running aegis, CI pipelines included, before they can update. Once the fix is out, the advisory is published with the full details.

## Supported versions

Security fixes go into the latest release on [pub.dev](https://pub.dev/packages/aegis). Update with `dart pub global activate aegis` before reporting, in case the problem is already fixed.

## Reporting a vulnerability

Please do **not** open a public issue for a vulnerability in aegis itself.

Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**, or go directly to <https://github.com/khaledSayedAbdellah/aegis/security/advisories/new>.

Include:

* the aegis version (`aegis --version`) and your OS;
* the command you ran and, if relevant, a minimal project, APK, AAB or IPA that triggers the problem;
* what happened and what an attacker gains from it.

You will get a reply as soon as possible. Once a fix is released, the advisory is published with credit to you unless you prefer otherwise.

## What counts as a vulnerability

aegis reads untrusted input (source projects, `aegis.yaml`, APK, AAB and IPA files) and writes reports that people open in a browser. Examples of issues to report privately:

* a crafted project, archive or binary that makes aegis run commands, write files outside its output folder, or hang or crash in a way that blocks CI;
* HTML or Markdown reports that run script or load remote content from data in the audited app;
* secrets from the audited app appearing unredacted in a report;
* aegis sending project data anywhere other than [osv.dev](https://osv.dev) for the dependency check (skipped with `--offline`);
* the resilience probe changing host or device security settings it does not document.

## Not a vulnerability in aegis

These belong in a normal [issue](https://github.com/khaledSayedAbdellah/aegis/issues/new/choose):

* a finding that is wrong (false positive) or a problem aegis misses (false negative);
* a vulnerability in the app you audited: that is what the report is for;
* a vulnerability in a third-party tool aegis calls (adb, Frida, the Android emulator, Xcode). Report those to the tool's maintainers.
