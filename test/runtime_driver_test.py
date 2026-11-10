import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

DRIVER = Path(__file__).resolve().parents[1] / 'lib/src/security/runtime_driver.py'
spec = importlib.util.spec_from_file_location('runtime_driver', DRIVER)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class RuntimeDriverTests(unittest.TestCase):
    def test_marker_variants_are_redacted_and_labelled(self):
        value = 'synthetic_secret_1234'
        for data in [value.encode(), value.encode('utf-16le'), driver.base64.b64encode(value.encode())]:
            self.assertEqual(driver.marker_hits(data, {'password': value}), ['password'])
        self.assertEqual(driver.marker_hits(b'other content', {'password': value}), [])

    def test_timeout_and_output_limits_stop_commands(self):
        with self.assertRaises(RuntimeError):
            driver.command([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=.1)
        with self.assertRaises(RuntimeError):
            driver.command([sys.executable, '-c', 'print("x" * 10000)'], cap=100)

    def test_cleanup_runs_when_scenario_fails_without_exposing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            runner = path / 'runner.py'
            runner.write_text('''import os,json,sys
from pathlib import Path
if os.environ['AEGIS_PHASE']=='cleanup':
    Path('cleaned').write_text('yes');print(json.dumps({'completed':True}))
else:
    print('should-never-appear-in-report');sys.exit(1)
''')
            result = driver.run({'command':[sys.executable,str(runner)], 'device':'emulator-5554','app_id':'app.test','build':'1','platform':'android','artifact':'fixture.apk','root':tmp,'hosts':[],'timeout_seconds':2})
            self.assertTrue(result['cleanup'])
            self.assertFalse(result['baseline'])
            self.assertNotIn('should-never', json.dumps(result))
            self.assertTrue((path/'cleaned').exists())

    def test_android_collects_process_logs_and_tar_without_extracting_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)
            adb=path/'adb'
            adb.write_text('''#!/usr/bin/env python3
import io,sys,tarfile
args=' '.join(sys.argv[1:])
if 'pidof' in args: print('123')
elif 'logcat' in args: print('synthetic_secret_1234')
elif 'tar' in args:
    with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as tar:
        data=b'synthetic_secret_1234';m=tarfile.TarInfo('../../escape');m.size=len(data);tar.addfile(m,io.BytesIO(data))
else: sys.exit(1)
''')
            adb.chmod(0o700)
            r=driver.inspect_storage({'app_id':'app.test','device':'unavailable-test-device','platform':'android','adb':str(adb)}, {'password':'synthetic_secret_1234'})
            self.assertTrue(r['channels']['files'])
            self.assertTrue(r['channels']['logs'])
            self.assertFalse(r['channels']['clipboard'])
            self.assertEqual({h['channel'] for h in r['hits']},{'files','logs'})
            self.assertFalse((path.parent/'escape').exists())
            self.assertNotIn('synthetic_secret',json.dumps(r))

    @unittest.skipUnless(os.environ.get('AEGIS_TEST_MITMDUMP'), 'set AEGIS_TEST_MITMDUMP for real proxy integration')
    def test_real_tls_interception_acceptance_and_rejection(self):
        # Real mitmproxy + TLS clients; only Android identity/runner is synthetic.
        # The proxy serves a fixture response, so no external server or host CA
        # installation is involved in this integration test.
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)
            addon=path/'response.py'
            addon.write_text("from mitmproxy import http\ndef request(flow):\n    flow.response=http.Response.make(200,b'fixture')\n")
            wrapper=path/'mitmdump'
            wrapper.write_text('#!'+sys.executable+'\nimport os,sys\nos.execv('+repr(os.environ['AEGIS_TEST_MITMDUMP'])+', ['+repr(os.environ['AEGIS_TEST_MITMDUMP'])+", '--set', 'upstream_cert=false', '--set', 'connection_strategy=lazy', '-s', "+repr(str(addon))+']+sys.argv[1:])\n')
            wrapper.chmod(0o700)
            adb=path/'adb'
            adb.write_text('#!'+sys.executable+"\nimport sys\nprint('aegis-probe-test\\nOK' if 'emu' in sys.argv else 'versionCode=1')\n")
            adb.chmod(0o700)
            runner=path/'scenario.py'
            runner.write_text('''import http.client,json,os,ssl
phase=os.environ['AEGIS_PHASE']
if phase in ['untrusted', 'trusted']:
    host,port=os.environ['AEGIS_PROXY'].split(':')
    context=ssl.create_default_context(cafile=os.environ['AEGIS_CA_CERT']) if phase=='trusted' else (ssl._create_unverified_context() if os.environ.get('AEGIS_FIXTURE_INSECURE')=='yes' else ssl.create_default_context())
    c=http.client.HTTPSConnection(host,int(port),context=context,timeout=10)
    c.set_tunnel('api.example.test',443)
    try:
        c.request('GET','/');r=c.getresponse();r.read();assert r.status==200
    except ssl.SSLCertVerificationError:
        assert os.environ.get('AEGIS_FIXTURE_INSECURE')!='yes'
    finally: c.close()
print(json.dumps({'completed':True,'reached_hosts':['api.example.test'] if phase=='baseline' else []}))
''')
            cfg={'command':[sys.executable,str(runner)],'device':'emulator-5554','app_id':'app.test','build':'1','platform':'android','artifact':'fixture.apk','root':tmp,'hosts':['api.example.test'],'timeout_seconds':15,'adb':str(adb),'mitmdump':str(wrapper)}
            old=os.environ.get('AEGIS_FIXTURE_INSECURE')
            try:
                for insecure in ['yes','no']:
                    os.environ['AEGIS_FIXTURE_INSECURE']=insecure
                    result=driver.run(cfg)
                    self.assertTrue(result['baseline'],result)
                    self.assertTrue(result['cleanup'],result)
                    self.assertEqual(result['errors'],[],result)
                    self.assertEqual(bool(result['network']),insecure=='yes',result)
                from mitmproxy.certs import CertStore
                ca_dir=path/'trusted-ca'
                CertStore.from_store(ca_dir,'mitmproxy',2048)
                cfg['trusted_ca_dir']=str(ca_dir)
                os.environ['AEGIS_FIXTURE_INSECURE']='no'
                trusted=driver.run(cfg)
                self.assertEqual(trusted['errors'],[],trusted)
                self.assertEqual(trusted['network'],[{'host':'api.example.test','phase':'trusted'}],trusted)
                # A failed application assertion must not erase accepted traffic.
                runner.write_text(runner.read_text().replace("print(json.dumps({'completed':True", "import sys\nif phase=='trusted': sys.exit(1)\nprint(json.dumps({'completed':True"))
                failed=driver.run(cfg)
                self.assertIn('trusted_scenario',failed['errors'])
                self.assertEqual(failed['network'],[{'host':'api.example.test','phase':'trusted'}],failed)
                self.assertTrue(failed['cleanup'])
            finally:
                if old is None:os.environ.pop('AEGIS_FIXTURE_INSECURE',None)
                else:os.environ['AEGIS_FIXTURE_INSECURE']=old


if __name__=='__main__':unittest.main()
