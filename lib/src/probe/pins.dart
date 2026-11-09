/// Every version `aegis setup` installs, so results are the same on every
/// machine and upgrading is one edit here.
///
/// To upgrade (see docs/plans/probe-toolchain.md §5.2): take the newest
/// `frida` on PyPI, a `frida-tools` whose `Requires-Dist` accepts it, and
/// check that `frida-server-<v>-android-arm64.xz` and
/// `bundletool-all-<v>.jar` exist in the GitHub releases.
library;

/// `frida` on PyPI; frida-server on the emulator must be the same version.
const fridaVersion = '17.26.2';

/// Requires frida >=17.26.0 <18.
const fridaToolsVersion = '14.13.0';

/// Installed only when no build-tools with apksigner + zipalign exist.
const buildToolsVersion = '36.0.0';

/// Oldest build-tools that has a usable apksigner (v2/v3 signing).
const minBuildToolsMajor = 30;

/// Android 14, Google APIs image (allows `adb root`; Play images don't).
const systemImageApi = 34;

const bundletoolVersion = '1.18.3';

/// The emulator aegis creates and uses.
const avdName = 'aegis-probe';
const controlAvdName = 'aegis-probe-control';

/// Device profile for the AVD.
const avdDevice = 'pixel_6';

const minJavaMajor = 17;
const minPython = (3, 9);

/// Free space wanted before downloading the system image (~1.5 GB, plus
/// the AVD's data).
const minFreeBytesForImage = 4 * 1024 * 1024 * 1024;

String fridaServerName(String arch) =>
    'frida-server-$fridaVersion-android-$arch';

String fridaServerUrl(String arch) =>
    'https://github.com/frida/frida/releases/download/$fridaVersion/'
    '${fridaServerName(arch)}.xz';

String get bundletoolName => 'bundletool-$bundletoolVersion.jar';

String get bundletoolUrl =>
    'https://github.com/google/bundletool/releases/download/$bundletoolVersion/'
    'bundletool-all-$bundletoolVersion.jar';

/// The SHA-256 and size of a pinned download, so a corrupted or tampered file
/// is caught. Verified against the real GitHub release assets on 2026-11-08.
class Pinned {
  const Pinned(this.sha256, this.bytes);
  final String sha256;
  final int bytes;
}

const _fridaServerPins = <String, Pinned>{
  'arm64': Pinned(
      '84519c157b76b9050cfcf197b530288040f8dca34d66341f5d5a688f792a3af9', 24687484),
  'x86_64': Pinned(
      '1f03e1bd3800618f6e6b4a978b84a7d093a2bdefd42722eb3f27e4c3bbfd2139', 44915484),
};

/// The pin for the frida-server `.xz` of [arch].
Pinned fridaServerPin(String arch) => _fridaServerPins[arch]!;

const bundletoolPin = Pinned(
    'a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29', 32520401);
