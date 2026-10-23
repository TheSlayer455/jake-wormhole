"""Authored local collector/transport fixtures; no Docker, SSH or package calls."""
import ast
import base64
from copy import deepcopy
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace,ModuleType
import unittest
from unittest.mock import patch

from validation import runtime
from test_validation import callback_event
from test_observed_svd import fixture
from wormhole.observed_svd import canonical


def collector_definitions(source=runtime.SVD_PROGRAM):
    """Load only authored definitions; never arm the target alarm in the test runner."""
    tree=ast.parse(source)
    tree.body=[node for node in tree.body if isinstance(node,(ast.Import,ast.ImportFrom,ast.FunctionDef)) or
        isinstance(node,ast.Assign) and all(isinstance(target,ast.Name) and target.id in {'ROOT','NAMES'} for target in node.targets)]
    namespace={};exec(compile(tree,'<fixed-software-inventory-definitions>','exec'),namespace);return namespace


def callback(results):
    class Base:pass
    modules={name:ModuleType(name) for name in ('ansible','ansible.plugins','ansible.plugins.callback')}
    modules['ansible'].__path__=[];modules['ansible.plugins'].__path__=[];modules['ansible.plugins.callback'].CallbackBase=Base
    namespace={'__name__':'fixed_inventory_callback_fixture'}
    with patch.dict(sys.modules,modules):exec(compile(runtime.SVD_CALLBACK_SOURCE,'<fixed-inventory-callback>','exec'),namespace)
    namespace['RESULTS']=results
    with patch.object(importlib.metadata,'version',return_value='2.21.5'):return namespace['CallbackModule']()


class NativeCollectors(unittest.TestCase):
    def test_dpkg_complete_versions_architecture_installed_status_and_held_installed_semantics(self):
        collect=collector_definitions()['dpkg_rows']
        raw=(b'libexample\t1:2.3-0ubuntu1.2\ti386\tinstalled\n'
             b'libexample\t1:2.3-0ubuntu1.2\tamd64\tinstalled\n'
             b'removed-example\t2.0\tall\tconfig-files\n')
        # A desired hold action still has db:Status-Status=installed. The fixed
        # query deliberately does not mistake desired action for actual status.
        values=collect(raw);self.assertEqual([row['architecture'] for row in values],['amd64','i386'])
        self.assertEqual(values[0]['version'],'1:2.3-0ubuntu1.2')
        for bad in (raw+raw.splitlines()[0]+b'\n',b'partial\t1\tamd64\thalf-installed\n',b'name\t1\tamd64\n',b''):
            with self.subTest(bad=bad[:30]),self.assertRaises(ValueError):collect(bad)

    def test_rpm_retains_full_nevra_parallel_versions_and_null_arch_virtual_keys(self):
        headers=[{'name':'kernel-example','epoch':None,'version':'1.0','release':'1.el9','arch':'x86_64'},
            {'name':'kernel-example','epoch':0,'version':'2.0','release':'1.el9','arch':'x86_64'},
            {'name':'gpg-pubkey','epoch':None,'version':'fd431d51','release':'4ae0493b','arch':None}]
        class Transaction:
            def dbMatch(self):return headers
            def closeDB(self):self.closed=True
        transaction=Transaction();module=SimpleNamespace(TransactionSet=lambda _:transaction)
        packages,keys=collector_definitions()['rpm_rows'](module)
        self.assertEqual([row['version'] for row in packages],['1.0','2.0']);self.assertTrue(transaction.closed)
        self.assertEqual(packages[0]['epoch'],0);self.assertIsNone(keys[0]['arch'])
        headers.append(deepcopy(headers[0]))
        with self.assertRaises(ValueError):collector_definitions()['rpm_rows'](module)
        headers.pop();headers[0]['epoch']=False
        with self.assertRaises(ValueError):collector_definitions()['rpm_rows'](module)

    @unittest.skipUnless(os.name=='posix','Synthetic local symlink filesystem fixture')
    def test_only_standard_os_release_link_is_permitted_while_payload_links_remain_refused(self):
        read=collector_definitions()
        with tempfile.TemporaryDirectory(prefix='wormhole-svd-release-synthetic-') as temporary:
            root=Path(temporary);(root/'etc').mkdir();(root/'usr/lib').mkdir(parents=True)
            canonical_path=root/'usr/lib/os-release';canonical_path.write_bytes(b'ID=ubuntu\nVERSION_ID="24.04"\nNAME="Synthetic"\n')
            path=root/'etc/os-release';path.symlink_to('../usr/lib/os-release')
            self.assertEqual(read['read_release'](path,canonical_path),canonical_path.read_bytes())
            with self.assertRaises(ValueError):read['read'](path,8192)
            path.unlink();path.symlink_to('/tmp/not-a-release')
            with self.assertRaises(ValueError):read['read_release'](path,canonical_path)

    @unittest.skipUnless(os.name=='posix','Authored local subprocess bounds fixture, no package tools')
    def test_actual_query_child_partial_error_overflow_and_deadline_never_yield_a_complete_database(self):
        query=collector_definitions(runtime.SVD_PROGRAM.replace('end=time.monotonic()+10','end=time.monotonic()+.1'))['query']
        for program,limit in (("import os;os.write(1,b'x'*10000)",1024),('import time;time.sleep(10)',1024),
            ("import sys;sys.stdout.write('partial');sys.exit(1)",1024),("import sys;sys.stderr.write('warning')",1024)):
            with self.subTest(program=program),self.assertRaises(ValueError):query([sys.executable,'-I','-B','-c',program],limit)


@unittest.skipUnless(os.name=='posix','Original fixed callback/private helper filesystem fixtures')
class FixedTransport(unittest.TestCase):
    def request(self):
        return {'schema_version':'1.0','run_id':'12345678-1234-4234-9234-123456789abc','source_revision':'a'*40,
            'target_id':'target-001','plan_sha256':'b'*64,'operation':'software-inventory-v1','address':'172.31.77.2',
            'scenario':'healthy','readiness_source_sha256':'c'*64,'timeout_seconds':5.}

    def test_callback_projects_one_packet_without_stdout_lines_or_command_duplication(self):
        packet=base64.b64encode(canonical(fixture()['observation'])).decode()
        with tempfile.TemporaryDirectory(prefix='wormhole-svd-callback-synthetic-') as temporary:
            results=Path(temporary);results.chmod(0o700);value=callback(results)
            command=['/usr/bin/python3','-I','-B','-c',runtime.SVD_PROGRAM]
            event=callback_event({'stdout':packet,'stdout_lines':[packet],'stderr':'','stderr_lines':[],'cmd':command,'rc':0})
            value.v2_runner_on_ok(event);value.v2_playbook_on_stats(None)
            record=json.loads((results/'target-001.json').read_bytes());self.assertEqual(record['result']['stdout'],packet)
            self.assertNotIn('cmd',record['result']);self.assertNotIn('stdout_lines',record['result'])
            self.assertEqual(record['result']['command_sha256'],hashlib.sha256(json.dumps(command,sort_keys=True,separators=(',',':')).encode()).hexdigest())
            self.assertLess((results/'target-001.json').stat().st_size,49152)

    def test_full_helper_collect_uses_fixed_command_and_packet_with_complete_single_host_event(self):
        for fault in ('healthy','duplicate','foreign','no-log','missing','bad-command','oversize'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory(prefix='wormhole-svd-helper-synthetic-') as temporary:
                root=Path(temporary);root.chmod(0o700)
                def write_private(path,raw):path.write_bytes(raw);path.chmod(0o600)
                rr=SimpleNamespace(ROOT=root,qualified_runtime=lambda:SimpleNamespace(identity=lambda:self.request()['run_id'],write_private=write_private),
                    prepare_auth=lambda *_:None,ssh_options=lambda _:['-o','StrictHostKeyChecking=yes'],environment=lambda:{'ANSIBLE_CONFIG':'fixed'})
                def capture(arguments,budget,environment):
                    self.assertEqual(arguments[0],'/opt/wormhole/venv/bin/ansible')
                    command=json.loads(arguments[arguments.index('-a')+1])['argv']
                    self.assertEqual(command,['/usr/bin/python3','-I','-B','-c',runtime.SVD_PROGRAM]);self.assertEqual(environment['ANSIBLE_CONFIG'],'fixed')
                    value=callback(root/'software-inventory/results')
                    packet=base64.b64encode(canonical(fixture()['observation'])).decode()
                    event=callback_event({'stdout':packet if fault!='oversize' else 'x'*43693,'cmd':command if fault!='bad-command' else ['/bin/sh'],'rc':0},
                        host='foreign' if fault=='foreign' else 'target-001',no_log=fault=='no-log')
                    if fault!='missing':value.v2_runner_on_ok(event)
                    if fault=='duplicate':value.v2_runner_on_ok(event)
                    value.v2_playbook_on_stats(None)
                    return {'returncode':0,'timed_out':False,'truncated':False,'log':'Synthetic bounded Ansible UI output'}
                rr.capture=capture
                with patch.object(importlib.metadata,'version',return_value='2.21.5'):
                    if fault=='bad-command':
                        with self.assertRaises(ValueError):runtime.collect_software_inventory(self.request(),rr)
                    else:
                        result=runtime.collect_software_inventory(self.request(),rr)
                        self.assertEqual(result['status'],'pass' if fault=='healthy' else 'error')
                        self.assertEqual(result['collector_base64'] is not None,fault=='healthy')


if __name__=='__main__':unittest.main()
