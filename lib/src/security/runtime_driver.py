"""Aegis scenario driver: no host proxy, Keychain, SIP or trust-store changes.

Commands and device identifiers are supplied by the developer. All results are
bounded and redacted. A negative observation remains inconclusive. No validation
or pinning bypass script is injected into the application under test.
"""
import base64
import io
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import socket
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import hashlib

LIMIT = 32 * 1024 * 1024


def command(argv, timeout=30, env=None, cwd=None, cap=LIMIT, stdin_data=None):
    # Files rather than PIPE communicate buffers prevent unbounded child output.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err, tempfile.TemporaryFile() as inp:
        if stdin_data is not None:
            inp.write(stdin_data)
            inp.seek(0)
        child = subprocess.Popen(argv, stdin=inp, stdout=out, stderr=err, env=env, cwd=cwd, start_new_session=os.name != 'nt')
        def stop():
            try:
                if os.name != 'nt':
                    os.killpg(child.pid, signal.SIGKILL)
                else:
                    child.kill()
            except ProcessLookupError:
                pass
        end = time.monotonic() + timeout
        try:
            while child.poll() is None:
                if time.monotonic() > end or out.tell() > cap or err.tell() > cap:
                    stop()
                    child.wait()
                    raise RuntimeError('command limit')
                time.sleep(.05)
            out.seek(0)
            data = out.read(cap + 1)
            if len(data) > cap:
                raise RuntimeError('output limit')
            return child.returncode, data
        finally:
            stop()
            if child.poll() is None:
                child.wait()



def make_script(session, source):
    # Frida 17 moves Java/ObjC bridges out of core. Use the installed
    # frida-tools bridge at runtime; no bridge code is vendored into Aegis.
    symbol = 'Java' if 'Java' in source else 'ObjC'
    try:
        import frida_tools
        bridge = Path(frida_tools.__file__).parent / 'bridges' / (symbol.lower() + '.js')
        prefix = "if (typeof " + symbol + " === 'undefined') {" + bridge.read_text() + ";globalThis." + symbol + "=bridge;}\n"
    except (ImportError, OSError):
        prefix = ''
    return session.create_script(prefix + source)


def worker(action, cfg, markers=None):
    payload = dict(cfg, markers=markers or {})
    code, data = command([sys.executable, __file__, action], timeout=60,
                         stdin_data=json.dumps(payload).encode())
    if code:
        raise RuntimeError('collector failed')
    return json.loads(data)

def marker_hits(data, markers):
    result = []
    for name, value in markers.items():
        raw = value.encode()
        variants = [raw, value.encode('utf-16le'), value.encode('utf-16be'), base64.b64encode(raw)]
        if any(v in data for v in variants):
            result.append(name)
    return result


def inspect_storage(cfg, markers):
    """Collect only the target sandbox, process logs and clipboard."""
    result = {'hits': [], 'channels': {}, 'limited': False}

    def inspect(channel, data):
        result['channels'][channel] = True
        for name in marker_hits(data, markers):
            result['hits'].append({'marker': name, 'channel': channel})

    app, device, platform = cfg['app_id'], cfg['device'], cfg['platform']
    if platform == 'android':
        adb = cfg.get('adb', 'adb')
        prefix = [adb, '-s', device]
        try:
            code, pid = command(prefix + ['shell', 'pidof', app])
            pid = pid.decode().strip().split()[0]
            if code or not pid.isdigit():
                raise RuntimeError('No target PID')
            code, logs = command(prefix + ['logcat', '-d', '--pid=' + pid, '-v', 'brief'])
            if code:
                raise RuntimeError('logcat unavailable')
            inspect('logs', logs)
        except Exception:
            result['channels']['logs'] = False
        try:
            code, data = command(prefix + ['exec-out', 'run-as', app, 'tar', '-cf', '-', '.'])
            if code or not data:
                code, data = command(prefix + ['exec-out', 'su', '0', 'tar', '-C', '/data/user/0/' + app, '-cf', '-', '.'])
            if code:
                raise RuntimeError('sandbox unavailable')
            total = 0
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
                for member in archive:
                    if not member.isfile():
                        continue
                    total += member.size
                    if member.size > 4 * 1024 * 1024 or total > LIMIT:
                        result['limited'] = True
                        continue
                    f = archive.extractfile(member)
                    if f:
                        inspect('files', f.read(4 * 1024 * 1024))
            result['channels']['files'] = True
        except Exception:
            result['channels']['files'] = False
        # Optional Frida clipboard reader; never modifies certificate validation.
        try:
            import frida
            dev = frida.get_device(device, timeout=5)
            session = dev.attach(int(pid))
            try:
                script = make_script(session, '''rpc.exports = {read: function() {
                    return new Promise(function(resolve, reject) {
                      if (typeof Java === 'undefined') { reject('Java bridge unavailable'); return; }
                      Java.perform(function() { try {
                        const app = Java.use('android.app.ActivityThread').currentApplication();
                        const c = Java.cast(app.getSystemService('clipboard'), Java.use('android.content.ClipboardManager'));
                        const clip = c.getPrimaryClip(); let s = '';
                        if (clip) for(let i=0;i<clip.getItemCount();i++) s += clip.getItemAt(i).coerceToText(app).toString();
                        resolve(s);
                      } catch(e) { reject(String(e)); } });
                    });
                }};''')
                script.load()
                inspect('clipboard', script.exports_sync.read().encode())
            finally:
                session.detach()
        except Exception:
            result['channels']['clipboard'] = False
    elif platform == 'ios-simulator':
        try:
            code, data = command(['xcrun', 'simctl', 'pbpaste', device])
            if code:
                raise RuntimeError('clipboard unavailable')
            inspect('clipboard', data)
        except Exception:
            result['channels']['clipboard'] = False
        try:
            code, data = command(['xcrun', 'simctl', 'get_app_container', device, app, 'data'])
            if code:
                raise RuntimeError('sandbox unavailable')
            root = Path(data.decode().strip()).resolve(strict=True)
            total = 0
            for path in root.rglob('*'):
                if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
                    continue
                size = path.stat().st_size
                total += size
                if size > 4 * 1024 * 1024 or total > LIMIT:
                    result['limited'] = True
                    continue
                data = path.read_bytes()
                inspect('files', data)
                if path.suffix == '.plist':
                    try:
                        inspect('files', repr(plistlib.loads(data)).encode())
                    except Exception:
                        pass
            result['channels']['files'] = True
        except Exception:
            result['channels']['files'] = False
        try:
            name = cfg['executable']
            if not re.fullmatch(r'[\w.+-]+', name):
                raise RuntimeError('invalid process name')
            code, data = command(['xcrun', 'simctl', 'spawn', device, 'log', 'show', '--last', '2m', '--style', 'json', '--predicate', 'process == "' + name + '"'])
            if code:
                raise RuntimeError('logs unavailable')
            inspect('logs', data)
        except Exception:
            result['channels']['logs'] = False
    else:
        # Stock physical iOS does not expose another application's sandbox.
        # A configured Frida device can collect from inside the target process.
        try:
            import frida
            dev = frida.get_device(device, timeout=5)
            app_info = next(a for a in dev.enumerate_applications() if a.identifier == app and a.pid)
            session = dev.attach(app_info.pid)
            try:
                script = make_script(session, '''rpc.exports = { collect: function() {
                  if(typeof ObjC === 'undefined' || !ObjC.available) throw Error('ObjC unavailable');
                  const fm=ObjC.classes.NSFileManager.defaultManager();
                  const home=new ObjC.Object(new NativeFunction(Module.getGlobalExportByName('NSHomeDirectory'),'pointer',[])());
                  const iter=fm.enumeratorAtPath_(home); let item; let files=[]; let total=0; let limited=false;
                  while((item=iter.nextObject())!==null) {
                    const path=home.toString()+'/'+item.toString();
                    const attrs=fm.attributesOfItemAtPath_error_(path,NULL);
                    if(!attrs || attrs.objectForKey_('NSFileType').toString()!=='NSFileTypeRegular') continue;
                    const size=Number(attrs.objectForKey_('NSFileSize').toString()); total+=size;
                    if(size>4194304 || total>33554432) {limited=true;continue;}
                    try {files.push(Array.from(new Uint8Array(File.readAllBytes(path))));} catch(e) {limited=true;}
                  }
                  const value=ObjC.classes.UIPasteboard.generalPasteboard().string();
                  return {files:files, clipboard:value?value.toString():'', limited:limited};
                }};''')
                script.load()
                data = script.exports_sync.collect()
                for content in data['files']:
                    inspect('files', bytes(content))
                result['channels']['files'] = True
                inspect('clipboard', data['clipboard'].encode())
                result['limited'] |= data['limited']
            finally:
                session.detach()
        except Exception:
            result['channels'].update(files=False, clipboard=False)
        result['channels']['logs'] = False
    return result


def verify_target(cfg):
    if cfg['platform'] == 'android':
        prefix = [cfg.get('adb', 'adb'), '-s', cfg['device']]
        code, name = command(prefix + ['emu', 'avd', 'name'])
        if code or not name.decode().splitlines()[0].startswith('aegis-probe'):
            raise RuntimeError('A dedicated Aegis emulator is required')
        code, data = command(prefix + ['shell', 'dumpsys', 'package', cfg['app_id']])
        match = re.search(rb'\bversionCode=(\d+)\b', data)
        if code or not match or match[1].decode() != cfg['build']:
            raise RuntimeError('Installed Android build mismatch')
    elif cfg['platform'] == 'ios-simulator':
        code, data = command(['xcrun', 'simctl', 'get_app_container', cfg['device'], cfg['app_id'], 'app'])
        if code:
            raise RuntimeError('Simulator application unavailable')
        info = plistlib.loads((Path(data.decode().strip()) / 'Info.plist').read_bytes())
        if str(info.get('CFBundleVersion')) != cfg['build'] or info.get('CFBundleIdentifier') != cfg['app_id']:
            raise RuntimeError('Simulator build mismatch')
    else:
        # Identity/build must be inspected in-process, not merely a runner claim.
        import frida
        dev = frida.get_device(cfg['device'], timeout=5)
        app = next(a for a in dev.enumerate_applications() if a.identifier == cfg['app_id'] and a.pid)
        session = dev.attach(app.pid)
        try:
            script = make_script(session, '''rpc.exports={identity:function(){const b=ObjC.classes.NSBundle.mainBundle();return {id:b.bundleIdentifier().toString(),build:b.infoDictionary().objectForKey_('CFBundleVersion').toString()};}};''')
            script.load()
            info = script.exports_sync.identity()
            if info['id'] != cfg['app_id'] or info['build'] != cfg['build']:
                raise RuntimeError('Physical iOS build mismatch')
        finally:
            session.detach()


ADDON = r'''
import json, os
from mitmproxy import http
hosts=set(json.loads(os.environ['AEGIS_CAPTURE_HOSTS']))
def request(flow: http.HTTPFlow):
    # Capture metadata only, never URLs, credentials, headers or bodies.
    if flow.request.host in hosts and flow.request.scheme == 'https':
        with open(os.environ['AEGIS_CAPTURE_FILE'], 'a') as f:
            f.write(json.dumps({'host':flow.request.host,'kind':'https_request'})+'\n')
'''


def run(cfg):
    result = {'baseline': False, 'network': [], 'storage': {}, 'errors': [], 'cleanup': False}
    command_args = cfg['command']
    markers = cfg.get('markers', {})
    env = os.environ.copy()
    env.update(AEGIS_DEVICE=cfg['device'], AEGIS_PLATFORM=cfg['platform'],
               AEGIS_APP_ID=cfg['app_id'], AEGIS_ARTIFACT=cfg['artifact'],
               AEGIS_BUILD=cfg['build'])

    def scenario(phase, proxy='', ca=''):
        local = dict(env, AEGIS_PHASE=phase, AEGIS_PROXY=proxy, AEGIS_CA_CERT=ca)
        code, data = command(command_args, timeout=cfg['timeout_seconds'], env=local, cwd=cfg['root'], cap=1024*1024)
        if code:
            raise RuntimeError('Scenario failed')
        payload = json.loads(data.decode().splitlines()[-1])
        if not isinstance(payload, dict) or payload.get('completed') is not True:
            raise RuntimeError('Scenario did not complete its assertions')
        return payload

    try:
        scenario('prepare')
        if worker('--verify', cfg) is not True:
            raise RuntimeError('Target mismatch')
        baseline = scenario('baseline')
        if worker('--verify', cfg) is not True:
            raise RuntimeError('Target mismatch')
        result['baseline'] = True
        result['baseline_hosts'] = [h for h in baseline.get('reached_hosts', []) if h in cfg['hosts']]
        if markers:
            result['storage'] = worker('--storage', cfg, markers)
        for phase in ['untrusted', 'trusted']:
            if not cfg['hosts'] or phase == 'trusted' and not cfg.get('trusted_ca_dir'):
                continue
            proxy = None
            try:
                with tempfile.TemporaryDirectory(prefix='aegis-traffic-') as tmp:
                    directory = Path(tmp)
                    (directory / 'capture.py').write_text(ADDON)
                    capture = directory / 'events.jsonl'
                    conf = directory / 'ca'
                    conf.mkdir()
                    if phase == 'trusted':
                        # Copy only the proxy certificate/key; never write to the supplied CA directory.
                        src = Path(cfg['trusted_ca_dir']) / 'mitmproxy-ca.pem'
                        shutil.copyfile(src, conf / 'mitmproxy-ca.pem')
                        os.chmod(conf / 'mitmproxy-ca.pem', 0o600)
                        code, _ = command(['openssl', 'x509', '-in', str(conf / 'mitmproxy-ca.pem'), '-out', str(conf / 'mitmproxy-ca-cert.pem')])
                        if code:
                            raise RuntimeError('Invalid proxy CA')
                    with socket.socket() as sock:
                        sock.bind(('127.0.0.1', 0))
                        port = sock.getsockname()[1]
                    proxy_env = dict(env, AEGIS_CAPTURE_HOSTS=json.dumps(cfg['hosts']), AEGIS_CAPTURE_FILE=str(capture))
                    proxy = subprocess.Popen([cfg.get('mitmdump', 'mitmdump'), '--listen-host', '127.0.0.1', '--listen-port', str(port), '--set', 'confdir=' + str(conf), '-s', str(directory / 'capture.py'), '-q'], env=proxy_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    ready = False
                    for _ in range(100):
                        if proxy.poll() is not None:
                            break
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                                ready = True
                                break
                        except OSError:
                            time.sleep(.1)
                    if not ready:
                        raise RuntimeError('Proxy unavailable')
                    try:
                        scenario(phase, '127.0.0.1:' + str(port), str(conf / 'mitmproxy-ca-cert.pem'))
                    except Exception:
                        result['errors'].append(phase + '_scenario')
                    finally:
                        proxy.terminate()
                        try:
                            proxy.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            proxy.kill()
                            proxy.wait()
                    if capture.exists():
                        if capture.stat().st_size > 1024*1024:
                            raise RuntimeError('Capture limit')
                        for line in capture.read_text().splitlines():
                            event = json.loads(line)
                            if event['host'] in result['baseline_hosts']:
                                result['network'].append({'phase': phase, 'host': event['host']})
            except Exception:
                result['errors'].append(phase)
            finally:
                if proxy is not None and proxy.poll() is None:
                    proxy.kill()
                    proxy.wait()
    except Exception:
        result['errors'].append('scenario_or_target')
    finally:
        try:
            scenario('cleanup')
            result['cleanup'] = True
        except Exception:
            result['errors'].append('cleanup')
    return result


if __name__ == '__main__':
    try:
        config = json.loads(sys.stdin.buffer.read(1024*1024))
        if '--verify' in sys.argv:
            verify_target(config)
            print('true')
        elif '--storage' in sys.argv:
            print(json.dumps(inspect_storage(config, config['markers'])))
        else:
            print(json.dumps(run(config)))
    except Exception:
        # Child diagnostics may contain secrets. Never reflect exception text.
        print(json.dumps({'baseline': False, 'network': [], 'storage': {}, 'errors': ['driver'], 'cleanup': False}))
