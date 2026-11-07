"""Builds the small APK fixtures used by test/apk_test.dart.

They are synthetic but structurally real: binary XML (AXML) manifests,
a zip with an APK Signing Block (v2) and a v1 PKCS#7 signature file.

    pip install cryptography
    python3 tool/make_apk_fixtures.py

Writes test/fixtures/apk/{vulnerable,secure,debug}.apk and expected.json.
"""
import base64
import datetime
import hashlib
import io
import json
import os
import struct
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

OUT = os.path.join(os.path.dirname(__file__), '..', 'test', 'fixtures', 'apk')
ANDROID = 'http://schemas.android.com/apk/res/android'
ATTR_IDS = {
    'name': 0x01010003, 'permission': 0x01010006, 'debuggable': 0x0101000f,
    'exported': 0x01010010, 'minSdkVersion': 0x0101020c, 'versionCode': 0x0101021b,
    'versionName': 0x0101021c, 'targetSdkVersion': 0x01010270, 'maxSdkVersion': 0x01010271,
    'allowBackup': 0x01010280, 'usesCleartextTraffic': 0x010104ec,
    'networkSecurityConfig': 0x01010527,
}
NONE = 0xFFFFFFFF


# --------------------------------------------------------------------- AXML
def el(tag, attrs=None, children=None):
    """attrs: list of (is_android, name, value). value: bool|int|str|('ref', id)."""
    return (tag, attrs or [], children or [])


def axml(root, utf8=False, strip_android_names=False):
    android_names, others = [], []

    def collect(node):
        tag, attrs, children = node
        for is_android, name, value in attrs:
            if is_android and name in ATTR_IDS:
                if name not in android_names:
                    android_names.append(name)
            elif name not in others:
                others.append(name)
            if isinstance(value, str) and value not in others:
                others.append(value)
        if tag not in others:
            others.append(tag)
        for c in children:
            collect(c)

    collect(root)
    strings = list(android_names)
    for s in ['android', ANDROID] + others:
        if s not in strings:
            strings.append(s)
    idx = {s: i for i, s in enumerate(strings)}
    pool_strings = ['' if (strip_android_names and i < len(android_names)) else s
                    for i, s in enumerate(strings)]

    def chunk(type_, header_size, body_header, body):
        size = 8 + len(body_header) + len(body)
        return struct.pack('<HHI', type_, header_size, size) + body_header + body

    # string pool
    data = b''
    offsets = []
    for s in pool_strings:
        offsets.append(len(data))
        if utf8:
            enc = s.encode('utf-8')
            data += bytes([len(s)]) + bytes([len(enc)]) + enc + b'\x00'
        else:
            data += struct.pack('<H', len(s)) + s.encode('utf-16-le') + b'\x00\x00'
    while len(data) % 4:
        data += b'\x00'
    strings_start = 28 + 4 * len(pool_strings)
    sp_header = struct.pack('<IIIII', len(pool_strings), 0, 0x100 if utf8 else 0, strings_start, 0)
    sp = chunk(0x0001, 28, sp_header, b''.join(struct.pack('<I', o) for o in offsets) + data)

    resmap = chunk(0x0180, 8, b'', b''.join(struct.pack('<I', ATTR_IDS[n]) for n in android_names))

    body = b''
    body += chunk(0x0100, 16, struct.pack('<II', 1, NONE), struct.pack('<II', idx['android'], idx[ANDROID]))

    def emit(node):
        nonlocal body
        tag, attrs, children = node
        attr_bytes = b''
        for is_android, name, value in attrs:
            ns = idx[ANDROID] if is_android else NONE
            if isinstance(value, bool):
                raw, dtype, d = NONE, 0x12, (0xFFFFFFFF if value else 0)
            elif isinstance(value, int):
                raw, dtype, d = NONE, 0x10, value
            elif isinstance(value, tuple):
                raw, dtype, d = NONE, 0x01, value[1]
            else:
                raw, dtype, d = idx[value], 0x03, idx[value]
            attr_bytes += struct.pack('<IIIHBBI', ns, idx[name], raw, 8, 0, dtype, d)
        ext = struct.pack('<IIHHHHHH', NONE, idx[tag], 20, 20, len(attrs), 0, 0, 0)
        body += chunk(0x0102, 16, struct.pack('<II', 1, NONE), ext + attr_bytes)
        for c in children:
            emit(c)
        body += chunk(0x0103, 16, struct.pack('<II', 1, NONE), struct.pack('<II', NONE, idx[tag]))

    emit(root)
    body += chunk(0x0101, 16, struct.pack('<II', 1, NONE), struct.pack('<II', idx['android'], idx[ANDROID]))
    content = sp + resmap + body
    return struct.pack('<HHI', 0x0003, 8, 8 + len(content)) + content


# ------------------------------------------------------------ certificates
def make_cert(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Android'),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    now = datetime.datetime(2024, 1, 1)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=10000))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER), cert


def signing_block(cert_der):
    def lp(b):
        return struct.pack('<I', len(b)) + b
    signed_data = lp(b'') + lp(lp(cert_der)) + lp(b'')
    signer = lp(signed_data) + lp(b'') + lp(b'')
    value = lp(lp(signer))
    pair = struct.pack('<QI', 4 + len(value), 0x7109871a) + value
    size = len(pair) + 8 + 16
    return struct.pack('<Q', size) + pair + struct.pack('<Q', size) + b'APK Sig Block 42'


def build_apk(path, files, cert_der=None, v1_cert=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED if name.endswith('.so') else zipfile.ZIP_DEFLATED
            z.writestr(info, data)
        if v1_cert is not None:
            z.writestr('META-INF/CERT.RSA', pkcs7.serialize_certificates([v1_cert], serialization.Encoding.DER))
    data = buf.getvalue()
    if cert_der is not None:
        eocd = data.rfind(b'PK\x05\x06')
        cd = struct.unpack('<I', data[eocd + 16:eocd + 20])[0]
        block = signing_block(cert_der)
        data = data[:cd] + block + data[cd:]
        eocd += len(block)
        data = data[:eocd + 16] + struct.pack('<I', cd + len(block)) + data[eocd + 20:]
    with open(path, 'wb') as f:
        f.write(data)


def jwt(payload):
    def b64(o):
        return base64.urlsafe_b64encode(json.dumps(o, separators=(',', ':')).encode()).rstrip(b'=').decode()
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64(payload)}.c2lnbmF0dXJlLW5vdC1yZWFs"


def fake_so(strings):
    out = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 56
    for i, s in enumerate(strings):
        out += bytes([0x01, 0x8c, i % 7, 0x00]) + s.encode() + b'\x00\x00'
    return out


def main():
    os.makedirs(OUT, exist_ok=True)
    expected = {}
    service_jwt = jwt({'iss': 'supabase', 'ref': 'abcdefgh', 'role': 'service_role'})
    anon_jwt = jwt({'iss': 'supabase', 'ref': 'abcdefgh', 'role': 'anon'})

    # ------------------------------------------------------------ vulnerable
    manifest = el('manifest', [(False, 'package', 'com.myshop.app'), (True, 'versionCode', 7),
                               (True, 'versionName', '1.2.0')], [
        el('uses-sdk', [(True, 'minSdkVersion', 21), (True, 'targetSdkVersion', 33)]),
        el('uses-permission', [(True, 'name', 'android.permission.INTERNET')]),
        el('uses-permission', [(True, 'name', 'android.permission.READ_SMS')]),
        el('uses-permission', [(True, 'name', 'android.permission.QUERY_ALL_PACKAGES')]),
        el('uses-permission', [(True, 'name', 'android.permission.WRITE_EXTERNAL_STORAGE'),
                               (True, 'maxSdkVersion', 28)]),
        el('application', [(True, 'debuggable', True), (True, 'allowBackup', True),
                           (True, 'usesCleartextTraffic', True),
                           (True, 'networkSecurityConfig', ('ref', 0x7f150001))], [
            el('activity', [(True, 'name', 'com.myshop.app.MainActivity'), (True, 'exported', True)], [
                el('intent-filter', [], [
                    el('action', [(True, 'name', 'android.intent.action.MAIN')]),
                    el('category', [(True, 'name', 'android.intent.category.LAUNCHER')]),
                ]),
            ]),
            el('receiver', [(True, 'name', 'com.someplugin.SmsReceiver'), (True, 'exported', True)]),
            el('receiver', [(True, 'name', 'com.google.firebase.iid.FirebaseInstanceIdReceiver'),
                            (True, 'exported', True),
                            (True, 'permission', 'com.google.android.c2dm.permission.SEND')]),
            el('service', [(True, 'name', 'com.myshop.app.SyncService'), (True, 'exported', True)]),
        ]),
    ])
    nsc = el('network-security-config', [], [
        el('base-config', [(False, 'cleartextTrafficPermitted', 'true')], [
            el('trust-anchors', [], [
                el('certificates', [(False, 'src', 'system')]),
                el('certificates', [(False, 'src', 'user')]),
            ]),
        ]),
    ])
    layout = el('LinearLayout', [(True, 'name', 'unused')])
    debug_der, debug_cert = make_cert('Android Debug')
    build_apk(os.path.join(OUT, 'vulnerable.apk'), {
        'AndroidManifest.xml': axml(manifest),
        'res/xml/nsc.xml': axml(nsc, utf8=True),
        'res/layout/main.xml': axml(layout, utf8=True),
        'classes.dex': b'dex\n035\x00' + b'\x00' * 32 + b'\x10com/someplugin/SmsReceiver\x00',
        'resources.arsc': b'\x02\x00\x0c\x00' + b'\x00' * 16,
        'lib/arm64-v8a/libflutter.so': fake_so(['FlutterEngine']),
        'lib/arm64-v8a/libapp.so': fake_so([
            '_kDartIsolateSnapshotData',
            'AKIAIOSFODNN7EXAMPLE',            # also in example/vulnerable_app source
            service_jwt,                        # only in the binary: --dart-define
            anon_jwt,                           # public key, must be ignored
            '_MaterialAppState', '_WidgetsAppState', '_NavigatorState', '_OverlayState',
            'LoginScreenController', 'PaymentRepository',
            # A PEM key with data after the header: a real leak.
            '-----BEGIN PRIVATE KEY-----',
            'THISISNOTAREALKEYTHISISNOTAREALKEYTHISISNOTAREALKEY0123456789ab',
            '-----END PRIVATE KEY-----',
        ]),
        'assets/flutter_assets/AssetManifest.json': b'{}',
        'assets/flutter_assets/.env': b'API_SECRET=abc\n',
        'assets/flutter_assets/assets/config.json': b'{"aws":"AKIAI44QH8DHBEXAMPLE"}',
    }, cert_der=debug_der, v1_cert=debug_cert)
    expected['vulnerable'] = {
        'sha256Base64': base64.b64encode(hashlib.sha256(debug_der).digest()).decode(),
        'commonName': 'Android Debug',
        'serviceJwt': service_jwt,
    }

    # ---------------------------------------------------------------- secure
    secure_manifest = el('manifest', [(False, 'package', 'com.acme.bank'), (True, 'versionCode', 42),
                                      (True, 'versionName', '3.0.0')], [
        el('uses-sdk', [(True, 'minSdkVersion', 24), (True, 'targetSdkVersion', 35)]),
        el('uses-permission', [(True, 'name', 'android.permission.INTERNET')]),
        el('application', [(True, 'allowBackup', False)], [
            el('activity', [(True, 'name', 'com.acme.bank.MainActivity'), (True, 'exported', True)], [
                el('intent-filter', [], [
                    el('action', [(True, 'name', 'android.intent.action.MAIN')]),
                    el('category', [(True, 'name', 'android.intent.category.LAUNCHER')]),
                ]),
            ]),
        ]),
    ])
    release_der, _ = make_cert('Acme Release')
    build_apk(os.path.join(OUT, 'secure.apk'), {
        # Attribute names stripped from the string pool, as some obfuscators do.
        'AndroidManifest.xml': axml(secure_manifest, strip_android_names=True),
        'classes.dex': b'dex\n035\x00' + b'\x00' * 32,
        'lib/arm64-v8a/libflutter.so': fake_so(['FlutterEngine']),
        # PEM markers alone, as in apps that use basic_utils/pointycastle: not a leak.
        # One framework name can survive --obfuscate (seen in real apps).
        'lib/arm64-v8a/libapp.so': fake_so(['_kDartIsolateSnapshotData', 'Xk2', 'aB9', 'qZ_', anon_jwt, '_RenderTheater',
                                            '-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----',
                                            '-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----']),
        'assets/flutter_assets/AssetManifest.json': b'{}',
    }, cert_der=release_der)
    expected['secure'] = {
        'sha256Base64': base64.b64encode(hashlib.sha256(release_der).digest()).decode(),
        'commonName': 'Acme Release',
    }

    # ----------------------------------------------------------------- debug
    debug_manifest = el('manifest', [(False, 'package', 'com.acme.dev')], [
        el('uses-sdk', [(True, 'minSdkVersion', 24), (True, 'targetSdkVersion', 35)]),
        el('application', [(True, 'allowBackup', False)]),
    ])
    build_apk(os.path.join(OUT, 'debug.apk'), {
        'AndroidManifest.xml': axml(debug_manifest),
        'lib/x86_64/libflutter.so': fake_so(['FlutterEngine']),
        'assets/flutter_assets/kernel_blob.bin': b'\x90\xab\xcd\xef' * 16,
    }, cert_der=release_der)

    with open(os.path.join(OUT, 'expected.json'), 'w') as f:
        json.dump(expected, f, indent=2)
    print('fixtures written to', os.path.normpath(OUT))


if __name__ == '__main__':
    main()
