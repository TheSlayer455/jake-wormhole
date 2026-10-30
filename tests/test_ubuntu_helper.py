"""Synthetic controller failure propagation; real VM runs are separate evidence."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


@unittest.skipUnless(os.name=='posix','VM controller requires Linux')
class Helper(unittest.TestCase):
    def test_password_required_helper_reaches_ansible_with_private_become_input(self):
        from wormhole.ubuntu_runtime import HELPER_CODE
        calls=[];password='synthetic-password'
        def run(args,**kwargs):
            calls.append(args)
            if args[0]=='ssh':
                self.assertNotIn('sudo -n true',args[-1])
                self.assertIn('installation-complete',args[-1])
                return subprocess.CompletedProcess(args,0,'/dev/mapper/root\n','')
            if args[1:]==['--version']:
                return subprocess.CompletedProcess(args,0,'fixture version','')
            secret=Path(args[args.index('--become-password-file')+1])
            self.assertEqual(secret.read_text(),password+'\n')
            self.assertEqual(secret.stat().st_mode & 0o777,0o600)
            self.assertNotIn(password,' '.join(args))
            if '-b' in args:raise SystemExit(0) # Stop after the actual generated dispatch boundary.
            return subprocess.CompletedProcess(args,0,'fixture ping','')
        with tempfile.TemporaryDirectory() as value:
            code=HELPER_CODE.replace("pathlib.Path('/tmp/vm-credentials')","pathlib.Path("+repr(str(Path(value)/'credentials'))+")")
            stdin=io.StringIO(json.dumps({'address':'192.0.2.10','host_key':'fixture-public-host-key',
                'private_key':'synthetic-key-fixture','become_password':password,'seconds':90}))
            output=io.StringIO()
            with patch('subprocess.run',side_effect=run),patch.object(sys,'stdin',stdin),contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit) as stopped:
                    exec(compile(code,'synthetic-helper','exec'),{'__name__':'__main__'})
            self.assertEqual(stopped.exception.code,0)
            self.assertEqual(sum('-b' in args for args in calls),1)
            self.assertNotIn(password,output.getvalue())

    def test_non_json_privileged_output_still_generates_a_failed_complete_grid(self):
        from wormhole.ubuntu_runtime import report
        from wormhole.ubuntu_assessment import POLICY
        with tempfile.TemporaryDirectory() as value:
            root=Path(value)
            record={'stage':'installed-observations','returncode':0,'output':'PAM notice\n{}'}
            (root/'ssh-ansible-inventory.log').write_text(json.dumps(record)+'\n')
            result={'run_id':'fixture','source_revision':'fixture','outcome':'failed',
                    'cleanup':'verified-absent-inputs-retained','error_category':'ssh-ansible-inventory_failed'}
            actual=report(root,result)
            self.assertEqual(actual['functional_counts'],{'blocked':len(json.loads(POLICY.read_text())['functional_checks'])})
            self.assertFalse(actual['lab_iso_qualified'])
            self.assertTrue((root/'junit.xml').is_file())

    def test_confirmed_authentication_rejection_blocks_catalog_promptly(self):
        from wormhole.ubuntu_runtime import HELPER_CODE
        calls=[]
        def run(args,**kwargs):
            calls.append(args)
            if args[0].endswith('/ansible') and args[1:]==['--version']:
                return subprocess.CompletedProcess(args,0,'fixture version','')
            if args[0]=='ssh':
                return subprocess.CompletedProcess(args,255,'','Permission denied (publickey).')
            self.fail('Catalog started despite failed readiness: '+repr(args))
        with tempfile.TemporaryDirectory() as value:
            code=HELPER_CODE.replace("pathlib.Path('/tmp/vm-credentials')","pathlib.Path("+repr(str(Path(value)/'credentials'))+")")
            stdin=io.StringIO(json.dumps({'address':'192.0.2.10','host_key':'fixture-public-host-key',
                'private_key':'synthetic-key-fixture','become_password':'synthetic-password','seconds':900}))
            output=io.StringIO()
            with patch('subprocess.run',side_effect=run),patch('time.sleep'),patch.object(sys,'stdin',stdin),contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit) as stopped:
                    exec(compile(code,'synthetic-helper','exec'),{'__name__':'__main__'})
            self.assertEqual(stopped.exception.code,1)
            self.assertEqual(sum(args[0]=='ssh' for args in calls),3)
            last=json.loads(output.getvalue().splitlines()[-1])
            self.assertEqual(last['error_category'],'final-identity-authentication-rejected')
            self.assertFalse(last['catalog_started'])
