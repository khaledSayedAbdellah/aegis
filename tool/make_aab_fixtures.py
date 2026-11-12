"""Builds the Android App Bundle fixtures used by test/aab_test.dart.

The manifests and res/xml files are encoded with Google's protobuf library
from aapt2's own Resources.proto (tool/proto, Apache 2.0), so the Dart
decoder is checked against an independent encoder.

    pip install cryptography protobuf grpcio-tools
    python3 tool/make_aab_fixtures.py

Writes test/fixtures/aab/{vulnerable,secure}.aab and expected.json.
"""
import base64
import hashlib
import importlib
import io
import json
import os
import subprocess
import sys
import tempfile
import zipfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

sys.path.insert(0, os.path.dirname(__file__))
from make_apk_fixtures import ANDROID, ATTR_IDS, el, fake_so, jwt, make_cert  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'test', 'fixtures', 'aab')


def load_pb():
    gen = tempfile.mkdtemp()
    proto_root = os.path.join(HERE, 'proto')
    files = ['frameworks/base/tools/aapt2/Resources.proto',
             'frameworks/base/tools/aapt2/Configuration.proto']
    subprocess.check_call([sys.executable, '-m', 'grpc_tools.protoc', f'-I{proto_root}',
                           f'--python_out={gen}', *files])
    sys.path.insert(0, gen)
    return importlib.import_module('frameworks.base.tools.aapt2.Resources_pb2')


pb = load_pb()


def resource_table(file_path, service_jwt):
    table = pb.ResourceTable()
    table.source_pool.data = service_jwt.encode()
    package = table.package.add()
    package.package_id.id = 0x7f
    package.package_name = 'com.myshop.app'
    resource_type = package.type.add()
    resource_type.type_id.id = 0x15
    resource_type.name = 'xml'
    entry = resource_type.entry.add()
    entry.entry_id.id = 1
    entry.name = 'nsc'
    entry.config_value.add().value.item.file.path = file_path
    return table.SerializeToString()


def proto_xml(root, compiled_only=()):
    """root: el(...) tree. Attributes named in compiled_only get no raw
    `value` string, only a compiled item, to exercise the fallback."""
    def build(node, element, is_root):
        tag, attrs, children = node
        element.name = tag
        if is_root:
            ns = element.namespace_declaration.add()
            ns.prefix = 'android'
            ns.uri = ANDROID
        for is_android, name, value in attrs:
            a = element.attribute.add()
            a.name = name
            if is_android:
                a.namespace_uri = ANDROID
                if name in ATTR_IDS:
                    a.resource_id = ATTR_IDS[name]
            item = a.compiled_item
            if isinstance(value, bool):
                raw = 'true' if value else 'false'
                item.prim.boolean_value = value
            elif isinstance(value, int):
                raw = str(value)
                item.prim.int_decimal_value = value
            elif isinstance(value, tuple) and value[0] == 'ref':
                raw = '@' + value[2]
                item.ref.id = value[1]
                item.ref.name = value[2]
            else:
                raw = value
                a.ClearField('compiled_item')
            if name not in compiled_only:
                a.value = raw
        for c in children:
            n = element.child.add()
            build(c, n.element, False)

    node = pb.XmlNode()
    build(root, node.element, True)
    return node.SerializeToString()


def build_aab(path, files, v1_cert=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
        if v1_cert is not None:
            # jarsigner puts the bundle signature at the root, like a JAR.
            z.writestr('META-INF/UPLOAD.RSA', pkcs7.serialize_certificates([v1_cert], serialization.Encoding.DER))
    with open(path, 'wb') as f:
        f.write(buf.getvalue())


def main():
    os.makedirs(OUT, exist_ok=True)
    expected = {}
    service_jwt = jwt({'iss': 'supabase', 'ref': 'abcdefgh', 'role': 'service_role'})

    # ------------------------------------------------------------ vulnerable
    manifest = el('manifest', [(False, 'package', 'com.myshop.app'), (True, 'versionCode', 7),
                               (True, 'versionName', '1.2.0')], [
        el('uses-sdk', [(True, 'minSdkVersion', 21), (True, 'targetSdkVersion', 33)]),
        el('uses-permission', [(True, 'name', 'android.permission.INTERNET')]),
        el('uses-permission', [(True, 'name', 'android.permission.READ_SMS')]),
        el('application', [(True, 'debuggable', True), (True, 'allowBackup', True),
                           (True, 'usesCleartextTraffic', True),
                           (True, 'networkSecurityConfig', ('ref', 0x7f150001, 'xml/nsc'))], [
            el('activity', [(True, 'name', 'com.myshop.app.MainActivity'), (True, 'exported', True)], [
                el('intent-filter', [], [
                    el('action', [(True, 'name', 'android.intent.action.MAIN')]),
                    el('category', [(True, 'name', 'android.intent.category.LAUNCHER')]),
                ]),
            ]),
            el('receiver', [(True, 'name', 'com.someplugin.SmsReceiver'), (True, 'exported', True)]),
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
    debug_der, debug_cert = make_cert('Android Debug')
    build_aab(os.path.join(OUT, 'vulnerable.aab'), {
        'BundleConfig.pb': b'\x0a\x05\x0a\x031.0',
        # debuggable, minSdkVersion and networkSecurityConfig only as compiled items.
        'base/manifest/AndroidManifest.xml': proto_xml(
            manifest, compiled_only={'debuggable', 'minSdkVersion', 'networkSecurityConfig'}),
        'base/res/xml/unused.xml': proto_xml(el('network-security-config')),
        'base/res/a.xml': proto_xml(nsc),
        'base/resources.pb': resource_table('res/a.xml', service_jwt),
        'base/dex/classes.dex': b'dex\n035\x00' + b'\x00' * 32 + b'\x10com/someplugin/SmsReceiver\x00',
        'base/lib/arm64-v8a/libflutter.so': fake_so(['FlutterEngine']),
        'base/lib/arm64-v8a/libapp.so': fake_so([
            '_kDartIsolateSnapshotData', 'AKIAIOSFODNN7EXAMPLE',
            '_MaterialAppState', '_WidgetsAppState', '_NavigatorState', '_OverlayState',
            'LoginScreenController', 'PaymentRepository',
        ]),
        'base/assets/flutter_assets/AssetManifest.json': b'{}',
        'base/assets/flutter_assets/.env': b'API_SECRET=abc\n',
        'base/root/META-INF/kotlinx_coroutines_core.version': b'1.7.3',
        # A dynamic feature module with its own code.
        'feature_pay/manifest/AndroidManifest.xml': proto_xml(el('manifest', [(False, 'package', 'com.myshop.app')])),
        'feature_pay/dex/classes.dex': b'dex\n035\x00' + b'\x00' * 32 + b'AKIAZ7QW3RT5YU8IO2PL\x00',
        # Shipped to Play only, never installed: must not be scanned.
        'BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map': b'# AKIAJ5Q7R2D9EXAMPLE1\n',
    }, v1_cert=debug_cert)
    expected['vulnerable'] = {
        'sha256Base64': base64.b64encode(hashlib.sha256(debug_der).digest()).decode(),
        'commonName': 'Android Debug',
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
    upload_der, upload_cert = make_cert('Acme Upload')
    build_aab(os.path.join(OUT, 'secure.aab'), {
        'BundleConfig.pb': b'\x0a\x05\x0a\x031.0',
        'base/manifest/AndroidManifest.xml': proto_xml(secure_manifest),
        'base/dex/classes.dex': b'dex\n035\x00' + b'\x00' * 32,
        'base/lib/arm64-v8a/libflutter.so': fake_so(['FlutterEngine']),
        'base/lib/arm64-v8a/libapp.so': fake_so(['_kDartIsolateSnapshotData', 'Xk2', 'aB9', 'qZ_', '_RenderTheater']),
        'base/assets/flutter_assets/AssetManifest.json': b'{}',
    }, v1_cert=upload_cert)
    expected['secure'] = {
        'sha256Base64': base64.b64encode(hashlib.sha256(upload_der).digest()).decode(),
        'commonName': 'Acme Upload',
    }

    # Text form of the vulnerable manifest, for the decoder test.
    node = pb.XmlNode()
    with zipfile.ZipFile(os.path.join(OUT, 'vulnerable.aab')) as z:
        node.ParseFromString(z.read('base/manifest/AndroidManifest.xml'))
    expected['vulnerable']['manifestElements'] = len(str(node).split('element {')) - 1

    with open(os.path.join(OUT, 'expected.json'), 'w') as f:
        json.dump(expected, f, indent=2)
    print('fixtures written to', os.path.normpath(OUT))


if __name__ == '__main__':
    main()
