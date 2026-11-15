#!/usr/bin/env bash
# Installs aegis, runs it with the action's inputs and publishes the results:
# step outputs, annotations and the job summary. The exit code of aegis is
# returned as the `exit-code` output; the action's last step fails the job.
set -uo pipefail

truthy() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    true | yes | on | 1) return 0 ;;
    *) return 1 ;;
  esac
}

output() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"
  else
    printf 'output %s=%s\n' "$1" "$2"
  fi
}

workspace="${GITHUB_WORKSPACE:-$PWD}"
project="${AEGIS_PATH:-.}"
out="${AEGIS_OUTPUT_DIR:-aegis-report}"
case "$out" in
  /* | [A-Za-z]:[\\/]*) ;;
  *) out="$workspace/$out" ;;
esac
mkdir -p "$out"

dart="${AEGIS_DART:-dart}"
# Without a version input, install the aegis release this action release was
# published with (written by aegis's publish workflow), or the latest.
action_dir="$(cd "$(dirname "$0")/.." && pwd)"
if [ -z "${AEGIS_VERSION:-}" ] && [ -f "$action_dir/aegis-version.txt" ]; then
  AEGIS_VERSION="$(tr -d '[:space:]' <"$action_dir/aegis-version.txt")"
fi
if [ -z "${AEGIS_SKIP_INSTALL:-}" ]; then
  echo "::group::Install aegis ${AEGIS_VERSION:-(latest)}"
  # Retried: pub.dev can be briefly unreachable, or still publishing a
  # version that was just released.
  installed=1
  for attempt in 1 2 3 4; do
    if [ -n "${AEGIS_VERSION:-}" ]; then
      "$dart" pub global activate aegis "$AEGIS_VERSION" && installed=0
    else
      "$dart" pub global activate aegis && installed=0
    fi
    [ "$installed" -eq 0 ] && break
    [ "$attempt" -lt 4 ] && echo "Retrying in $((attempt * 20)) seconds." && sleep $((attempt * 20))
  done
  echo "::endgroup::"
  if [ "$installed" -ne 0 ]; then
    echo "::error title=aegis::Could not install aegis ${AEGIS_VERSION:-} from pub.dev."
    exit 1
  fi
fi

formats="console,json,sarif,md,html"
truthy "${AEGIS_PDF:-false}" && formats="$formats,pdf"

args=("$project" --format "$formats" --output "$out/aegis" --lang "${AEGIS_LANG:-en}")
[ -n "${AEGIS_PROFILE:-}" ] && args+=(--profile "$AEGIS_PROFILE")
[ -n "${AEGIS_APK:-}" ] && args+=(--apk "$AEGIS_APK")
[ -n "${AEGIS_IPA:-}" ] && args+=(--ipa "$AEGIS_IPA")
[ -n "${AEGIS_FAIL_ON:-}" ] && args+=(--fail-on "$AEGIS_FAIL_ON")
[ -n "${AEGIS_MIN_SCORE:-}" ] && args+=(--min-score "$AEGIS_MIN_SCORE")
[ -n "${AEGIS_BASELINE:-}" ] && args+=(--baseline "$AEGIS_BASELINE")
truthy "${AEGIS_STRICT:-false}" && args+=(--strict)
truthy "${AEGIS_OFFLINE:-false}" && args+=(--offline)
truthy "${AEGIS_PUB_GET:-true}" || args+=(--no-pub-get)
if [ -n "${AEGIS_ARGS:-}" ]; then
  read -r -a extra <<<"$AEGIS_ARGS"
  args+=("${extra[@]}")
fi

if [ -n "${AEGIS_COMMAND:-}" ]; then
  read -r -a command <<<"$AEGIS_COMMAND"
else
  command=("$dart" pub global run aegis)
fi
echo "aegis ${args[*]}"
"${command[@]}" "${args[@]}"
code=$?

output exit-code "$code"
output report-dir "$out"
for kind in json sarif html md; do
  [ -f "$out/aegis.$kind" ] && output "$kind-file" "$out/aegis.$kind"
done

python=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1 &&
    "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 6))' 2>/dev/null; then
    python="$candidate"
    break
  fi
done
if [ -f "$out/aegis.json" ] && [ -n "$python" ]; then
  annotate=false
  truthy "${AEGIS_ANNOTATIONS:-true}" && annotate=true
  "$python" "$(dirname "$0")/report.py" "$out/aegis.json" "$out/aegis.sarif" \
    "$project" "$annotate"
elif [ -f "$out/aegis.json" ]; then
  echo "::warning title=aegis::Python is not installed: the score outputs and annotations are skipped."
fi

if truthy "${AEGIS_JOB_SUMMARY:-true}" && [ -f "$out/aegis.md" ] &&
  [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  # A step summary is limited to 1 MiB.
  limit=$((1000 * 1000))
  if [ "$(wc -c <"$out/aegis.md")" -gt "$limit" ]; then
    head -c "$limit" "$out/aegis.md" >>"$GITHUB_STEP_SUMMARY"
    printf '\n\n…The report is cut here. The full report is in the artifact.\n' >>"$GITHUB_STEP_SUMMARY"
  else
    cat "$out/aegis.md" >>"$GITHUB_STEP_SUMMARY"
  fi
fi

exit 0
