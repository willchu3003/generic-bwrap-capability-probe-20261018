import errno
import http.client
from http.server import HTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import contract
import probe
import server


class PolicyTests(unittest.TestCase):
    def test_normal_calls_and_thread_clone_allowed(self):
        blob = contract.program()
        for number in (0,1,3,9,11,59,60,202,231,257):
            with self.subTest(number=number):
                self.assertEqual(contract.evaluate(blob,number),0x7FFF0000)
        for flags in (0x10000,0x10100,0x7D0F00):
            self.assertEqual(contract.evaluate(blob,56,flags=flags),0x7FFF0000)

    def test_forbidden_calls_and_clone3_errno(self):
        blob = contract.program()
        calls = {'socket':41,'fork':57,'vfork':58,'ptrace':101,'setpgid':109,
                 'setsid':112,'unshare':272,'setns':308,'process_vm_readv':310,'process_vm_writev':311}
        for name, number in calls.items():
            with self.subTest(name=name):
                self.assertEqual(contract.evaluate(blob,number),0x00050000|errno.EPERM)
        for flags in (0,0x100,0x4000,0x4111):
            self.assertEqual(contract.evaluate(blob,56,flags=flags),0x00050000|errno.EPERM)
        self.assertEqual(contract.evaluate(blob,435),0x00050000|errno.ENOSYS)

    def test_unsupported_abis_killed(self):
        for arch, number in ((0xC00000B7,0),(0x40000003,0),(contract.ARCH,0x40000000),
                             (contract.ARCH,0x40000001),(contract.ARCH,0xFFFFFFFF)):
            self.assertEqual(contract.evaluate(contract.program(),number,arch=arch),0x80000000)


class ClassificationTests(unittest.TestCase):
    def test_safe_diagnostic_identifies_mount_step_without_paths(self):
        data=b'bwrap: Failed to make / slave: Permission denied\n'
        result=probe.safe_diagnostic(data)
        self.assertEqual(result['context'],'MOUNT_PROPAGATION')
        self.assertEqual(result['errno'],'EACCES')
        self.assertIn('failed to make',result['safe_excerpt'])
        self.assertNotIn('/',result['safe_excerpt'])
        # Diagnosis must not silently change the original outcome classification.
        self.assertEqual(probe.classify(data),('INCONCLUSIVE','SANDBOX_SETUP_OR_EXECUTION_ERROR'))

    def test_safe_diagnostic_redacts_arbitrary_values_and_is_bounded(self):
        data=(b'bwrap: Cannot execute /tmp/SECRET_PATH_123: No such file or directory\n'
              b'https://host.invalid/SECRET_URL SECRET_TOKEN_123 somebody@private.invalid\n')
        result=probe.safe_diagnostic(data)
        for marker in ('secret','private.invalid','host.invalid','somebody','/tmp'):
            self.assertNotIn(marker,result['safe_excerpt'])
        for word in result['safe_excerpt'].split():
            self.assertTrue(word in probe.SAFE_WORDS or word=='[redacted]')
        self.assertLessEqual(len(probe.safe_diagnostic(data*1000)['safe_excerpt'].encode()),384)
        self.assertTrue(probe.safe_diagnostic(data*1000)['excerpt_limited'])

    def test_dependency_and_resource_errors_are_not_kernel_rejection(self):
        for text in (b'error loading shared libraries',b'bwrap: No such file or directory',
                     b'Creating new namespace: No space left on device',b'Cannot allocate memory'):
            self.assertEqual(probe.classify(text)[0],'INCONCLUSIVE')
        self.assertEqual(probe.classify(b'Creating new namespace failed: Operation not permitted'),
                         ('INCOMPATIBLE_SCOPED','NAMESPACE_CREATION_DENIED'))
        self.assertEqual(probe.classify(b'No permissions to create new namespace'),
                         ('INCOMPATIBLE_SCOPED','NAMESPACE_CREATION_DENIED'))
        self.assertEqual(probe.classify(b'Failed to apply seccomp: Permission denied'),
                         ('INCOMPATIBLE_SCOPED','SECCOMP_ATTACH_DENIED'))

    def test_non_linux_is_inconclusive_without_spawning(self):
        with mock.patch('probe.platform.system',return_value='Other'), mock.patch('probe.subprocess.Popen') as spawn:
            self.assertEqual(probe.run_probe()['code'],'LINUX_AMD64_REQUIRED')
            spawn.assert_not_called()

    def test_required_command_has_no_optional_namespace_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, fd = probe.command(Path(temporary),False)
        self.assertIsNone(fd)
        for flag in ('--unshare-user','--unshare-pid','--unshare-net','--unshare-ipc',
                     '--unshare-uts','--cap-drop','--die-with-parent','--clearenv','--proc','--dev','--tmpfs'):
            self.assertIn(flag,args)
        self.assertNotIn('--unshare-user-try',args)
        self.assertNotIn('--unshare-all',args)
        for i, arg in enumerate(args):
            if arg == '--ro-bind':self.assertNotEqual(args[i+1],'/')


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.state = server.State()
        self.server = HTTPServer(('127.0.0.1',0),server.handler_for(self.state))
        self.thread = threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.01})
        self.thread.start()
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(2)
        self.assertFalse(self.thread.is_alive())
    def request(self,method,path,body=None):
        connection = http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=2)
        try:
            connection.request(method,path,body=body)
            result=connection.getresponse();return result.status,dict(result.getheaders()),result.read()
        finally:connection.close()

    def test_exact_get_and_head_routes_only(self):
        for path in ('/','/result','/healthz'):
            status,headers,body=self.request('GET',path)
            self.assertEqual(status,200);self.assertEqual(headers['Cache-Control'],'no-store')
            self.assertIsInstance(json.loads(body),dict)
        status,headers,body=self.request('HEAD','/result')
        self.assertEqual(status,200);self.assertEqual(body,b'')
        self.assertGreater(int(headers['Content-Length']),0)

    def test_upload_command_and_path_inputs_never_run_probe(self):
        with mock.patch('server.run_probe') as run:
            for method in ('POST','PUT','PATCH','DELETE','OPTIONS','TRACE','CONNECT'):
                status,_,body=self.request(method,'/result',b'UNTRUSTED_INPUT_SENTINEL')
                self.assertEqual(status,405);self.assertNotIn(b'UNTRUSTED_INPUT_SENTINEL',body)
            for path in ('/result?command=id','/upload','/../../etc/passwd','/result/anything'):
                status,_,body=self.request('GET',path)
                self.assertEqual(status,404)
                self.assertEqual(json.loads(body),{'code':'NOT_FOUND'})
            run.assert_not_called()
        self.assertEqual(self.state.snapshot()['outcome'],'PENDING')


if __name__ == '__main__': unittest.main(verbosity=2)
