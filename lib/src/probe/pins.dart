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
