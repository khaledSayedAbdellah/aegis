"""Turns the aegis JSON report into step outputs and annotations, and makes
the SARIF file's paths relative to the repository.

Usage: report.py <aegis.json> <aegis.sarif> <project path> <annotate: true|false>
"""

import json
import os
import sys

LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "notice"}
MAX_ANNOTATIONS = 50


def escape_data(value):
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(value):
    return escape_data(value).replace(":", "%3A").replace(",", "%2C")


def in_repository(project, path):
    """The path of a project file relative to the repository, or None for a
    location inside a binary (`app.apk!/AndroidManifest.xml`)."""
    if not path or "!" in path:
        return None
    if os.path.isabs(path):
        return None
    joined = os.path.normpath(os.path.join(project, path))
    return joined.replace(os.sep, "/")


def write_outputs(report):
    score = report.get("score") or {}
    summary = report.get("summary") or {}
    new = sum(
        1
        for rule in report.get("rules", [])
        if rule.get("status") == "failed"
        for finding in rule.get("findings", [])
        if not finding.get("baselined") and not finding.get("outsideChange")
    )
    values = {
        "score": score.get("value", ""),
        "grade": score.get("grade", ""),
        "new-findings": new,
        "critical": summary.get("critical", 0),
        "high": summary.get("high", 0),
        "medium": summary.get("medium", 0),
        "low": summary.get("low", 0),
    }
    target = os.environ.get("GITHUB_OUTPUT")
    lines = ["%s=%s\n" % (k, v) for k, v in values.items()]
    if target:
        with open(target, "a", encoding="utf-8") as f:
            f.writelines(lines)
    else:
        sys.stdout.writelines("output " + line for line in lines)


def annotate(report, project):
    shown = 0
    hidden = 0
    for rule in report.get("rules", []):
        if rule.get("status") != "failed":
            continue
        level = LEVELS.get(rule.get("severity"), "notice")
        for finding in rule.get("findings", []):
            if finding.get("baselined") or finding.get("outsideChange"):
                continue
            if shown >= MAX_ANNOTATIONS:
                hidden += 1
                continue
            props = ["title=%s" % escape_property("%s %s" % (rule.get("id", ""), rule.get("title", "")))]
            path = in_repository(project, finding.get("file"))
            if path:
                props.insert(0, "file=%s" % escape_property(path))
                if finding.get("line"):
                    props.insert(1, "line=%d" % finding["line"])
            message = finding.get("message", "")
            if finding.get("file") and not path:
                message = "%s (%s)" % (message, finding["file"])
            print("::%s %s::%s" % (level, ",".join(props), escape_data(message)))
            shown += 1
    if hidden:
        print("::notice title=aegis::%d more findings are in the report." % hidden)


def relocate_sarif(sarif_file, project):
    """aegis writes paths relative to the project; code scanning needs them
    relative to the repository."""
    if os.path.normpath(project) == "." or not os.path.isfile(sarif_file):
        return
    with open(sarif_file, encoding="utf-8") as f:
        sarif = json.load(f)
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            for location in result.get("locations", []):
                artifact = location.get("physicalLocation", {}).get("artifactLocation", {})
                path = in_repository(project, artifact.get("uri"))
                if path:
                    artifact["uri"] = path
    with open(sarif_file, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)


def main():
    json_file, sarif_file, project, annotations = sys.argv[1:5]
    with open(json_file, encoding="utf-8") as f:
        report = json.load(f)
    write_outputs(report)
    if annotations == "true":
        annotate(report, project)
    relocate_sarif(sarif_file, project)


if __name__ == "__main__":
    main()
