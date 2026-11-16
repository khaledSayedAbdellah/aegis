/// The lines changed since a git ref, for `--changed-since`.
library;

import 'dart:convert';
import 'dart:io';

/// Lines changed in each file, relative to the project root. A file mapped
/// to null is new: every line counts as changed.
class ChangedLines {
  ChangedLines(this.ref, this.files, {this.note});

  /// Set when the change could not be measured from the merge base.
  final String? note;

  /// The ref the change is measured from, as given.
  final String ref;
  final Map<String, Set<int>?> files;

  /// Whether a finding at [file]:[line] is part of the change. A finding
  /// without a line belongs to it when its file changed; one without a file
  /// (about the whole project) does not.
  bool contains(String? file, int? line) {
    if (file == null || !files.containsKey(file)) return false;
    final lines = files[file];
    if (lines == null || line == null) return true;
    return lines.contains(line);
  }

  /// Reads `git diff` in [root] against the merge base of [ref] and HEAD
  /// (or against [ref] itself when there is no merge base, as in a shallow
  /// clone), plus untracked files.
  static ChangedLines load(String root, String ref) {
    if (ref.startsWith('-')) {
      throw FormatException('"$ref" is not a git ref.');
    }
    // core.quotePath=false: names outside ASCII come back as they are, not
    // as "\330\265..." escapes.
    // git writes UTF-8 whatever the system code page (Windows).
    ProcessResult git(List<String> args) => Process.runSync(
        'git', ['-C', root, '-c', 'core.quotePath=false', ...args],
        stdoutEncoding: utf8, stderrEncoding: utf8);
    final verify = git(['rev-parse', '--verify', '--quiet', '$ref^{commit}']);
    if (verify.exitCode != 0) {
      throw FormatException(
          'git cannot find "$ref" in $root. Fetch it first (for a pull request: '
          'git fetch origin <base-branch>), or use fetch-depth: 0 in actions/checkout.');
    }
    final base = git(['merge-base', ref, 'HEAD']);
    final from = base.exitCode == 0 ? (base.stdout as String).trim() : ref;
    final note = base.exitCode == 0
        ? null
        : 'No common commit with $ref (a shallow clone?): comparing with $ref '
            'directly. That is exact for the merge commit GitHub checks out for '
            'a pull request; elsewhere, commits on $ref that HEAD lacks also '
            'count as changes.';
    final diff = git([
      'diff', '--relative', '--unified=0', '--no-color', '--no-ext-diff', //
      '--no-renames', from, '--',
    ]);
    if (diff.exitCode != 0) {
      throw FormatException(
          'git diff failed: ${(diff.stderr as String).trim()}');
    }
    final files = parse(diff.stdout as String);
    final untracked =
        git(['ls-files', '--others', '--exclude-standard', '--full-name', '.']);
    final prefix = git(['rev-parse', '--show-prefix']);
    final cut = prefix.exitCode == 0 ? (prefix.stdout as String).trim() : '';
    if (untracked.exitCode == 0) {
      for (final line in (untracked.stdout as String).split('\n')) {
        final f = line.trim();
        if (f.isEmpty) continue;
        files[f.startsWith(cut) ? f.substring(cut.length) : f] = null;
      }
    }
    return ChangedLines(ref, files, note: note);
  }

  /// Reads `git diff --unified=0` output: new files map to null, others to
  /// the line numbers added or changed on the new side.
  static Map<String, Set<int>?> parse(String diff) {
    final out = <String, Set<int>?>{};
    String? file;
    var isNew = false;
    final hunk = RegExp(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@');
    for (final line in diff.split('\n')) {
      if (line.startsWith('diff --git ')) {
        file = null;
        isNew = false;
      } else if (line.startsWith('new file mode')) {
        isNew = true;
      } else if (line.startsWith('+++ ')) {
        final path = line.substring(4).trim();
        if (path == '/dev/null') {
          file = null;
        } else {
          file = path.startsWith('b/') ? path.substring(2) : path;
          out[file] = isNew ? null : <int>{};
        }
      } else if (file != null && out[file] != null) {
        final m = hunk.firstMatch(line);
        if (m == null) continue;
        final start = int.parse(m[1]!);
        final count = m[2] == null ? 1 : int.parse(m[2]!);
        for (var i = 0; i < count; i++) {
          out[file]!.add(start + i);
        }
      }
    }
    return out;
  }
}
