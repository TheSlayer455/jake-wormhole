"""Source/fixture checks only; no test here claims an installed VM."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from wormhole import admission as a, vm_admission as v, vm_inputs as i
from wormhole import rhel_inputs as r
from wormhole import rhel_assessment as ra
from wormhole.runs import RunError, atomic_json, now
from test_admission import observed


class Inputs(unittest.TestCase):
    def test_valid_old_hash_does_not_hide_changed_boot_inputs(self):
        manifest = {'capability': 'ubuntu-iso-installation-baseline', 'source': dict(i.UBUNTU), 'candidate_sha256': 'a' * 64}
        boot = {'grub.cfg': b'current boot', 'loopback.cfg': b'current loopback'}
        i.verify_reuse(manifest, 'a' * 64, boot, dict(boot))
        with self.assertRaises(RunError) as failure:
            i.verify_reuse(manifest, 'a' * 64, boot, {**boot, 'grub.cfg': b'stale boot'})
        self.assertEqual(failure.exception.code, 'stale_candidate')
        for wrong in ({**manifest, 'capability': 'container-reference'},
                      {**manifest, 'source': {**i.UBUNTU, 'release': '24.04'}}):
            with self.assertRaises(RunError):
                i.verify_reuse(wrong, 'a' * 64, boot, boot)
        with self.assertRaises(RunError):
            i.verify_reuse(manifest, 'b' * 64, boot, boot)

    def test_boot_entries_preserve_iso_kernel_and_add_unattended_serial(self):
        original = 'set timeout=30\n linux /casper/vmlinuz  ---\n initrd /casper/initrd\n'
        result = i.boot_config(original)
        self.assertIn('timeout=1', result)
        self.assertIn('/casper/vmlinuz  autoinstall console=ttyS0,115200n8 ---', result)
        self.assertIn('initrd /casper/initrd', result)
        for wrong in ('linux /other/kernel ---', result):
            with self.assertRaises(RunError):
                i.boot_config(wrong)

    def test_seed_contains_no_bootstrap_or_private_key_and_retains_host_key(self):
        text = i.cloud_config(str(uuid4()), 'ssh-ed25519 ' + 'A' * 68, '192.0.2.10/24', '52:54:00:11:22:33')
        value = json.loads(text.split('\n', 1)[1])['autoinstall']
        self.assertNotIn('identity', value)
        self.assertEqual([], value['user-data']['users'])
        self.assertFalse(value['user-data']['ssh_deletekeys'])
        self.assertFalse(value['refresh-installer']['update'])
        self.assertFalse(value['ssh']['allow-pw'])
        self.assertIn('curtin', text)
        self.assertIn('WORMHOLE_INSTALLATION_FAILED', text)
        self.assertIn('lab.service', text)
        with self.assertRaises(RunError):
            i.cloud_config(str(uuid4()), 'ssh-ed25519 A;echo secret', '192.0.2.10/24', '52:54:00:11:22:33')

    def test_terraform_contract_is_empty_disk_real_cdrom_isolated_network(self):
        value = i.terraform_config('wormhole-vm-0123456789ab', '/lab/pool', '/lab/candidate.iso',
                                   '/lab/seed.iso', '192.0.2.0/24', '52:54:00:11:22:33', 1001, 1002)
        resource = value['resource']
        domain = resource['libvirt_domain']['run']
        self.assertEqual(domain['type'], 'kvm')
        self.assertEqual(domain['memory'], 8192)
        self.assertNotIn('kernel', domain)
        self.assertNotIn('firmware', domain)  # explicit BIOS profile
        self.assertIn('/domain/devices/graphics', domain['xml']['xslt'])
        self.assertIn("disk[@device='disk']/driver/@type", domain['xml']['xslt'])
        self.assertIn('name="type">qcow2', domain['xml']['xslt'])
        self.assertEqual(domain['boot_device']['dev'], ['hd', 'cdrom'])
        self.assertNotIn('source', resource['libvirt_volume']['disk'])
        self.assertEqual(domain['disk'][0], {'file': '${libvirt_volume.disk.id}'})
        self.assertIn('<owner>1001</owner><group>1002</group>', resource['libvirt_volume']['disk']['xml']['xslt'])
        self.assertIn('<mode>0600</mode>', resource['libvirt_volume']['disk']['xml']['xslt'])
        self.assertEqual(resource['libvirt_network']['run']['mode'], 'none')
        self.assertFalse(resource['libvirt_network']['run']['dhcp']['enabled'])
        smaller = i.terraform_config('wormhole-vm-0123456789ab', '/lab/pool', '/lab/candidate.iso',
            '/lab/seed.iso', '192.0.2.0/24', '52:54:00:11:22:33', 1001, 1002, disk_bytes=32 * 1024**3)
        self.assertEqual(smaller['resource']['libvirt_volume']['disk']['size'], 32 * 1024**3)
        self.assertEqual(resource['libvirt_volume']['disk']['size'], 64 * 1024**3)


class RHELInputs(unittest.TestCase):
    def config(self, **changes):
        values = {'identifier':str(uuid4()), 'public_key':'ssh-ed25519 ' + 'A' * 68,
                  'guest_address':'192.0.2.10/24', 'mac':'52:54:00:11:22:33',
                  'password_hash':'$6$synthetic$' + 'A' * 86}
        return r.kickstart(**{**values, **changes})

    def test_bios_boot_retains_stage2_and_rescue_without_direct_kernel_boot(self):
        prefix = "search --no-floppy --set=root -l '" + r.LABEL + "'\n"
        kernel = ' linux /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=' + r.LABEL
        original = 'set default="1"\nset timeout=60\n' + prefix + kernel + ' quiet\n' + kernel + ' inst.rescue quiet\n'
        changed = r.boot_config(original)
        self.assertIn('set default="0"\nset timeout=1', changed)
        self.assertIn(kernel + ' quiet inst.ks=hd:LABEL=WORMHOLEKS:/ks.cfg console=ttyS0,115200n8', changed)
        self.assertIn(kernel + ' inst.rescue quiet\n', changed)
        with self.assertRaises(RunError):r.boot_config(changed)
        with self.assertRaises(RunError):r.boot_config(original.replace(r.LABEL, 'WRONG-LABEL'))

    def test_seed_preserves_final_identity_selinux_and_installed_only_host_key(self):
        config = self.config()
        self.assertIn('cdrom\n', config)
        self.assertIn('selinux --enforcing', config)
        self.assertIn('ignoredisk --only-use=vda', config)
        self.assertIn('clearpart --all --initlabel --drives=vda', config)
        self.assertIn('user --name=lab.service', config)
        self.assertIn('PasswordAuthentication no', config)
        self.assertNotIn('PRIVATE KEY', config)
        self.assertNotIn('--gateway=', config)
        self.assertIn('%post --interpreter=/bin/bash --erroronfail', config)
        before, script = config.split("<<'READY'\n", 1)
        script, after = script.split('\nREADY\n', 1)
        self.assertNotIn('WORMHOLE_FINAL_HOST_KEY_BEGIN', before + after)
        self.assertIn('test "$VERSION_ID" = 10.0', script)
        self.assertIn('test "$(getenforce)" = Enforcing', script)
        self.assertIn('WORMHOLE_FINAL_HOST_KEY_BEGIN', script)
        self.assertIn('systemctl enable wormhole-ready.service', after)
        self.assertIn('install -d -m 0755 /var/lib/wormhole', config)
        for changes in ({'password_hash':'PLAINTEXT-NOT-ALLOWED'}, {'public_key':'ssh-ed25519 A; bad'}):
            with self.assertRaises(RunError):self.config(**changes)

    def test_reuse_rejects_other_os_source_changed_boot_and_changed_candidate(self):
        manifest = {'capability':r.CAPABILITY, 'source':dict(r.RHEL), 'candidate_sha256':'a' * 64}
        r.verify_reuse(manifest, 'a' * 64, b'current', b'current')
        for change in ({'capability':'ubuntu-iso-installation-baseline'}, {'source':dict(i.UBUNTU)}):
            with self.assertRaises(RunError):r.verify_reuse({**manifest, **change}, 'a' * 64, b'current', b'current')
        with self.assertRaises(RunError):r.verify_reuse(manifest, 'a' * 64, b'current', b'stale')
        with self.assertRaises(RunError):r.verify_reuse(manifest, 'b' * 64, b'current', b'current')

    def test_invalid_media_is_refused_before_build_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);source = root/'wrong.iso';source.write_bytes(b'NOT-AN-ISO')
            with self.assertRaises(RunError) as error:
                r.build_rhel(source, root/'candidate.iso', root/'inputs', str(uuid4()),
                    'ssh-ed25519 ' + 'A' * 68, '192.0.2.10/24', '52:54:00:11:22:33',
                    password_hash='$6$synthetic$' + 'A' * 86)
            self.assertEqual(error.exception.code, 'source_identity_mismatch')
            self.assertFalse((root/'inputs').exists())
            self.assertFalse((root/'candidate.iso').exists())


class RHELAssessment(unittest.TestCase):
    def test_hardened_collector_binds_content_reboot_complete_findings_and_original_inventory(self):
        import base64,hashlib,io,tarfile
        from wormhole import rhel_hardening as h
        result,receipt,inventory=RHELSVD().fixture();target='vm-'+result['run_id'][:8]
        content=('<Benchmark xmlns="'+ra.X[1:-1]+'"><version>0.1.82</version><Profile id="'+ra.PROFILE+'">'
            '<title>DISA STIG for Red Hat Enterprise Linux 10</title>'
            '<description>Checks align to Red Hat Enterprise Linux 10 V1R2.</description></Profile>'
            '<Rule id="one"/><Rule id="two"/><Rule id="'+h.SSSD_CERTMAP_RULE+'"/></Benchmark>').encode()
        pinned={**h.CONTENT,'sha256':hashlib.sha256(content).hexdigest(),'rules':3,'selected_rules':2}
        native=('<Benchmark xmlns="'+ra.X[1:-1]+'"><TestResult><profile idref="'+h.LAB_PROFILE+'"/>'
            '<target>'+target+'</target><rule-result idref="one"><result>pass</result></rule-result>'
            '<rule-result idref="two"><result>fail</result></rule-result>'
            '<rule-result idref="'+h.SSSD_CERTMAP_RULE+'"><result>notselected</result></rule-result>'
            '</TestResult></Benchmark>').encode()
        receipt.update(run_id=result['run_id'],target=target,content_sha256=pinned['sha256'],profile_id=h.LAB_PROFILE,
            scanner_exit=2,remediation_during_assessment=False,installation_boot_id=str(uuid4()),
            tailoring_sha256=h.installation_contract()['tailoring_sha256'])
        result['build'].update(capability=h.CAPABILITY,assessment_content=pinned,
            installation_contract={'tailoring_sha256':receipt['tailoring_sha256']})
        files={name:b'synthetic output' for name in ra.FILES}
        files.update({'datastream.xml':content,'xccdf.xml':native,'arf.xml':native,'receipt.json':json.dumps(receipt).encode()})
        archive=io.BytesIO()
        with tarfile.open(fileobj=archive,mode='w:gz') as tar:
            for name,raw in files.items():
                member=tarfile.TarInfo(name);member.size=len(raw);tar.addfile(member,io.BytesIO(raw))
        payload=archive.getvalue();checks=dict.fromkeys(ra.HARDENED_CHECKS,True);checks['audit-service']=False
        crypto={'openssl_providers':{'status':'observed','returncode':0,'stdout':'synthetic provider version',
            'stderr':'','truncated':False,'error':None},'virtualization':{'status':'error','returncode':1,
            'stdout':'none\n','stderr':'','truncated':False,'error':None}}
        rows=inventory+[{'stage':'hardened-functional','returncode':1,'checks':checks,'crypto_runtime':crypto},
            {'stage':'assessment-archive','returncode':0,'sha256':hashlib.sha256(payload).hexdigest(),
             'archive_base64':base64.b64encode(payload).decode()}]
        with patch.object(h,'CONTENT',pinned),tempfile.TemporaryDirectory() as directory:
            summary=ra.collect(Path(directory),result,rows)
            self.assertEqual(summary['native_counts'],{'pass':1,'fail':1,'notselected':1})
            self.assertEqual(summary['content_version'],'0.1.82');self.assertEqual(summary['benchmark'],'RHEL 10 STIG V1R2')
            self.assertEqual(summary['functional_counts'],{'pass':11,'fail':1})
            self.assertFalse(summary['all_functional_checks_pass']);self.assertFalse(summary['lab_iso_qualified'])
            self.assertEqual(summary['crypto_runtime'],{**crypto,'kernel_release':{'status':'missing'}})
            self.assertIn('synthetic provider version',(Path(directory)/'assessment.txt').read_text())
            self.assertEqual(json.loads((Path(directory)/'installed-svd.json').read_text())['packages'][0]['epoch'],'2')
            self.assertIn('All 3 rules accounted for',(Path(directory)/'assessment.txt').read_text())
        for changed in ({'assessment_content':{**pinned,'release':'other'}},{'capability':r.CAPABILITY}):
            with patch.object(h,'CONTENT',pinned),tempfile.TemporaryDirectory() as directory,self.assertRaises(RunError) as error:
                ra.collect(Path(directory),{**result,'build':{**result['build'],**changed}},rows)
            self.assertEqual(error.exception.code,'assessment_content_contract')
        with patch.object(h,'CONTENT',pinned):
            self.assertEqual(ra.read_results(content,native,expected_target=target,scanner_exit=2,hardened=True,
                expected_hash='a'*64)['content_sha256'],pinned['sha256'])
            with self.assertRaises(RunError):ra.read_results(content+b'changed',native,expected_target=target,scanner_exit=2,hardened=True)
            with self.assertRaises(RunError):ra.read_results(content,native.replace(b'>fail<',b'>notselected<'),expected_target=target,scanner_exit=2,hardened=True)
            with self.assertRaises(RunError):ra.read_results(content,native.replace(
                b'>notselected<', b'>pass<'),expected_target=target,scanner_exit=2,hardened=True)
        changed=content.replace(b'0.1.82',b'0.1.83')
        with patch.object(h,'CONTENT',{**pinned,'sha256':hashlib.sha256(changed).hexdigest()}),self.assertRaises(RunError) as metadata:
            ra.read_results(changed,native,expected_target=target,scanner_exit=2,hardened=True)
        self.assertEqual(metadata.exception.code,'assessment_content_metadata')

    def test_hardened_service_probe_distinguishes_inactive_service_from_tool_error(self):
        import subprocess
        namespace={}
        exec(ra.HARDENED_PROBE.split('\ndef encrypted(')[0],namespace)
        service_active=namespace['service_active']
        with patch.object(subprocess,'run') as run:
            run.return_value=subprocess.CompletedProcess([],0,stdout='active\n')
            self.assertTrue(service_active('auditd'))
            run.return_value=subprocess.CompletedProcess([],3,stdout='inactive\n')
            self.assertFalse(service_active('auditd'))
            run.return_value=subprocess.CompletedProcess([],1,stdout='')
            with self.assertRaises(subprocess.CalledProcessError):service_active('auditd')

    def test_hardened_probe_observes_the_declared_non_pki_contract(self):
        namespace={}
        exec(ra.HARDENED_PROBE.split('\nroot=',1)[0],namespace)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);plain=root/'plain.conf';certmap=root/'certmap.conf'
            plain.write_text('[sssd]\nservices = nss, pam\n')
            certmap.write_text('[certmap/example.test/rule]\nmatchrule = <SAN>.*\n')
            self.assertTrue(namespace['no_certmap']([plain]))
            self.assertFalse(namespace['no_certmap']([plain,certmap]))

    def test_hardened_helper_preserves_failed_checks_collects_scan_and_never_puts_password_in_argv(self):
        import contextlib,io,subprocess,sys,time
        from types import SimpleNamespace
        compile(ra.HARDENED_AUDIT_CODE,'<hardened-helper>','exec')
        self.assertIn('--tailoring-file /usr/local/share/wormhole/lab-tailoring.xml', ra.HARDENED_AUDIT_CODE)
        self.assertIn("['staff_u','staff_r','staff_t']", ra.HARDENED_AUDIT_CODE)
        self.assertIn("context('staff_u','sysadm_r','sysadm_t')", ra.HARDENED_PROBE)
        compile(ra.HARDENED_PROBE,'<read-only-guest-probe>','exec')
        self.assertNotIn('--remediate',ra.HARDENED_AUDIT_CODE)
        self.assertIn('/usr/share/xml/scap/ssg/content/',ra.RHEL_AUDIT_CODE)
        self.assertNotIn('become_password',ra.RHEL_AUDIT_CODE)
        secret='SYNTHETIC-NOT-A-CREDENTIAL';calls=[]
        crypto={'kernel_release':{'status':'observed','returncode':0,'stdout':'synthetic-kernel',
            'stderr':'','truncated':False,'error':None}}
        checks={name:True for name in ra.HARDENED_CHECKS if name!='password-required-sudo'};checks['audit-service']=False
        def run(args,**kwargs):
            calls.append((args,kwargs));self.assertNotIn(secret,json.dumps(args))
            if len(calls)==1:return SimpleNamespace(returncode=1,stdout=b'',stderr=b'')
            if len(calls)==2:return SimpleNamespace(returncode=0,stdout=b'staff_u:staff_r:staff_t:s0\n',stderr=b'')
            self.assertEqual(kwargs['input'],(secret+'\n').encode())
            return SimpleNamespace(returncode=0,stdout=json.dumps({'checks':checks,'crypto_runtime':crypto}).encode() if len(calls)==3 else b'synthetic archive',stderr=b'')
        output=io.StringIO()
        with patch.object(subprocess,'run',side_effect=run),contextlib.redirect_stdout(output),self.assertRaises(SystemExit) as stopped:
            exec(ra.HARDENED_AUDIT_CODE,{'c':{'address':'192.0.2.10','become_password':secret},'opts':[],
                'deadline':time.monotonic()+300,'json':json,'subprocess':subprocess,'sys':sys,'time':time})
        self.assertEqual(stopped.exception.code,1);self.assertNotIn(secret,output.getvalue())
        rows=[json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(set(rows[0]['checks']),set(ra.HARDENED_CHECKS));self.assertEqual(rows[0]['returncode'],1)
        self.assertEqual(rows[0]['crypto_runtime'],crypto)
        self.assertTrue(any(row.get('stage')=='assessment-archive' for row in rows))
        self.assertEqual(rows[-1]['outcome'],'hardened-functional-failed')
        self.assertEqual(len(calls),4)
        if sys.platform!='win32':
            namespace={};exec(ra.HARDENED_PROBE.split('\ndef encrypted(')[0],namespace)
            observe=namespace['crypto_observe']
            observed=observe([sys.executable,'-c','print("synthetic provider")'])
            self.assertEqual(observed['status'],'observed');self.assertEqual(observed['stdout'],'synthetic provider\n')
            limited=observe([sys.executable,'-c','import os;os.write(1,b"x"*16384);os.write(1,b"x")'])
            self.assertEqual(limited['status'],'error');self.assertTrue(limited['truncated'])
            self.assertEqual(len(limited['stdout']),8192)
            failed=observe([sys.executable,'-c','import sys;print("unavailable",file=sys.stderr);sys.exit(7)'])
            self.assertEqual(failed['status'],'error');self.assertEqual(failed['returncode'],7)
            self.assertEqual(failed['stderr'],'unavailable\n')
            with patch.object(subprocess,'run',side_effect=subprocess.TimeoutExpired('synthetic',10)):
                expired=observe(['synthetic'])
            self.assertEqual(expired['status'],'error');self.assertEqual(expired['error'],'TimeoutExpired')

    def test_native_coverage_preserves_findings_and_rejects_missing_or_wrong_identity(self):
        import hashlib
        content = ('<Benchmark xmlns="' + ra.X[1:-1] + '"><Profile id="' + ra.PROFILE + '"/>'
            '<Rule id="one"><title>First synthetic rule</title></Rule><Rule id="two"/></Benchmark>').encode()
        native = ('<Benchmark xmlns="' + ra.X[1:-1] + '"><TestResult><profile idref="' + ra.PROFILE + '"/>'
            '<target>synthetic</target><rule-result idref="one"><result>pass</result></rule-result>'
            '<rule-result idref="two"><result>fail</result></rule-result></TestResult></Benchmark>').encode()
        def parse(value, **changes):
            args = {'expected_target':'synthetic', 'scanner_exit':2,
                    'expected_hash':hashlib.sha256(content).hexdigest(), 'expected_rules':2}
            return ra.read_results(content, value, **{**args, **changes})
        observed = parse(native)
        self.assertEqual(observed['native_counts'], {'pass':1, 'fail':1})
        self.assertTrue(observed['coverage_complete'])
        self.assertFalse(observed['lab_iso_qualified'])
        self.assertFalse(observed['production_iso_eligible'])
        for value in (native.replace(b'<rule-result idref="two"><result>fail</result></rule-result>', b''),
                      native.replace(b'idref="two"', b'idref="one"'),
                      native.replace(ra.PROFILE.encode(), b'wrong-profile'),
                      native.replace(b'<target>synthetic</target>', b'')):
            with self.assertRaises(RunError):parse(value)
        with self.assertRaises(RunError):parse(native, expected_hash='0' * 64)
        with self.assertRaises(RunError):parse(native, scanner_exit=124)

    def test_native_archive_rejects_unexpected_paths_links_and_missing_outputs(self):
        import base64, hashlib, io, tarfile
        compile(ra.RHEL_AUDIT_CODE, '<rhel-audit-helper>', 'exec')
        self.assertNotIn('--remediate', ra.RHEL_AUDIT_CODE)
        self.assertIn('timeout --signal=TERM --kill-after=5', ra.RHEL_AUDIT_CODE)
        for name, link in (('../escaped', False), ('scan.log', True), ('scan.log', False)):
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode='w:gz') as tar:
                member = tarfile.TarInfo(name)
                if link:member.type = tarfile.SYMTYPE;member.linkname = '../escaped'
                else:member.size = 4
                tar.addfile(member, None if link else io.BytesIO(b'test'))
            payload = archive.getvalue()
            row = {'stage':'assessment-archive', 'returncode':0,
                   'sha256':hashlib.sha256(payload).hexdigest(), 'archive_base64':base64.b64encode(payload).decode()}
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(RunError):ra.collect(Path(directory), {'run_id':str(uuid4())}, [row])
                self.assertFalse((Path(directory)/'escaped').exists())


class RHELSVD(unittest.TestCase):
    def fixture(self):
        result={'run_id':str(uuid4()),'source_revision':'b'*40,'build':{'candidate_sha256':'a'*64}}
        receipt={'boot_id':str(uuid4()),'kernel':'6.12.0-lab'}
        rows=[{'stage':'inventory','returncode':0,'output':'decorated text is not parsed',
               'response':{'rc':0,'stdout_lines':['kernel|0|6.12.0|1.el10|x86_64',
                   'kernel|0|6.12.0|2.el10|x86_64','example|2|1.0|3.el10|noarch',
                   'gpg-pubkey|0|abcdef|1234|(none)']}}]
        return result,receipt,rows

    def test_native_versions_parallel_kernels_and_key_headers_render_from_one_capture(self):
        result,receipt,rows=self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory);value=ra.write_svd(path,result,rows,receipt)
            self.assertEqual(len(value['packages']),3)
            self.assertEqual(value['packages'][0]['epoch'],'2')
            self.assertIsNone(value['rpm_key_headers'][0]['architecture'])
            self.assertEqual(json.loads((path/'installed-svd.json').read_text()),value)
            self.assertIn('example 2 1.0 3.el10 noarch',(path/'installed-svd.txt').read_text())
            self.assertEqual(value['candidate_sha256'],result['build']['candidate_sha256'])

    def test_failed_empty_or_duplicate_inventory_never_writes_a_passing_svd(self):
        for fault in ('failed','empty','duplicate','missing'):
            result,receipt,rows=self.fixture()
            if fault=='failed':rows[0]['response']['rc']=1
            elif fault=='empty':rows[0]['response']['stdout_lines']=[]
            elif fault=='duplicate':rows[0]['response']['stdout_lines']*=2
            else:rows[0].pop('response')
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(RunError):ra.write_svd(Path(directory),result,rows,receipt)
                self.assertFalse((Path(directory)/'installed-svd.json').exists())


@unittest.skipUnless(os.name == 'posix', 'Linux private storage/flock fixtures')
class SharedAdmission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'infrastructure'
        self.patch = patch.object(a, 'CANONICAL_INFRASTRUCTURE_ROOT', self.root)
        self.patch.start()
        with a.AdmissionLease(self.root, str(uuid4()), 'a' * 40,
                              collector=lambda _: observed(), allow_synthetic=True) as lease:
            lease.finish(reconciliation_complete=True)

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def test_vm_exit_does_not_imply_cleanup_or_allow_container_admission(self):
        with v.VMLease(self.root, str(uuid4()), 'b' * 40) as lease:
            lease.intent('domain', 'owned-domain')
            status = a.infrastructure_status(self.root)
            self.assertEqual(status['admission']['state'], 'finished')
            self.assertEqual(status['vm_admission']['state'], 'active')
            with self.assertRaises(RunError):
                lease.finish()
        with self.assertRaises(RunError) as failure:
            with a.AdmissionLease(self.root, str(uuid4()), 'a' * 40,
                                  collector=lambda _: observed(), allow_synthetic=True):
                self.fail('Unreconciled VM admitted a container run')
        self.assertEqual(failure.exception.code, 'unreconciled_vm_run')

    def test_finished_vm_requires_durable_matching_archive(self):
        with v.VMLease(self.root, str(uuid4()), 'b' * 40) as lease:
            lease.intent('installer_iso', '/private/candidate.iso')
            lease.reconciled('installer_iso', '/private/candidate.iso', retained_input=True)
            lease.finish()
            identifier = lease.id
        v.require_vm_reconciled(self.root)
        (self.root / 'vm-history' / (identifier + '.json')).unlink()
        with self.assertRaises(OSError):
            v.require_vm_reconciled(self.root)

    def test_resume_can_only_reconcile_the_original_run(self):
        identifier = str(uuid4())
        with v.VMLease(self.root, identifier, 'b' * 40) as lease:
            lease.intent('pool', 'owned-pool')
        with self.assertRaises(RunError):
            with v.VMLease.resume(self.root, str(uuid4()), 'b' * 40):
                self.fail('Wrong run resumed')
        with v.VMLease.resume(self.root, identifier, 'b' * 40) as lease:
            with self.assertRaises(RunError):
                lease.intent('domain', 'new-allocation')
            lease.reconciled('pool', 'owned-pool')
            lease.finish()
        v.require_vm_reconciled(self.root)

    def test_vm_rejects_container_unreconciled_and_same_live_lock(self):
        with a.AdmissionLease(self.root, str(uuid4()), 'a' * 40,
                              collector=lambda _: observed(), allow_synthetic=True):
            with self.assertRaises(RunError):
                with v.VMLease(self.root, str(uuid4()), 'b' * 40):
                    self.fail('Concurrent backends admitted')
        with self.assertRaises(RunError) as failure:
            with v.VMLease(self.root, str(uuid4()), 'b' * 40):
                self.fail('Unreconciled container admitted a VM')
        self.assertEqual(failure.exception.code, 'unreconciled_container_run')

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Root-owned QEMU path fixture')
    def test_new_qemu_directory_traversal_survives_private_umask(self):
        from wormhole.vm_baseline import create_qemu_directory
        path = Path(self.temp.name) / 'qemu-share'
        previous = os.umask(0o077)
        try:
            create_qemu_directory(path, os.getgid())
        finally:
            os.umask(previous)
        self.assertEqual(path.stat().st_mode & 0o777, 0o710)
        with self.assertRaises(FileExistsError):
            create_qemu_directory(path, os.getgid())


class VMJournal(unittest.TestCase):
    def test_closed_backend_and_production_boundary(self):
        value = {'schema_version': '1.0', 'backend': 'libvirt-iso', 'run_id': str(uuid4()),
            'source_revision': 'b' * 40, 'state': 'active', 'created_at': now(), 'updated_at': now(),
            'resources': [{'kind': 'domain', 'identity': 'owned', 'outcome': 'pending'}],
            'production_iso_eligible': False}
        v.validate_record(value)
        for change in ({'backend': 'docker'}, {'production_iso_eligible': True}, {'state': 'finished'}):
            with self.assertRaises(RunError):
                v.validate_record({**value, **change})


@unittest.skipUnless(os.name=='posix','Linux supervisor process observations')
class VMExecution(unittest.TestCase):
    def test_finished_journal_terminalization_preserves_unknown_outcome_and_blocks_pending_checks(self):
        from subprocess import CompletedProcess
        from wormhole import ubuntu_recovery as recovery
        value={'outcome':'running','checks':{'ready':'pass','validation':'pending'},'cleanup':'pending'}
        observed=recovery.terminalize_reconciled(value)
        self.assertEqual(observed['outcome'],'unknown')
        self.assertEqual(observed['first_failure'],'supervisor_interrupted_without_terminal_result')
        self.assertEqual(observed['checks'],{'ready':'pass','validation':'blocked'})
        self.assertEqual(observed['cleanup'],'verified-absent-inputs-retained')
        self.assertEqual(observed['recovery']['original_outcome'],'running')
        with patch.object(recovery.subprocess,'run',return_value=CompletedProcess([],1)) as virsh:
            self.assertFalse(recovery.network_filter_present('owned-filter'))
        self.assertEqual(virsh.call_args.args[0],
            ['virsh','-c','qemu:///system','nwfilter-dumpxml','owned-filter'])

    def test_hardened_recovery_recognizes_only_the_run_owned_support_service(self):
        from contextlib import nullcontext
        from subprocess import CompletedProcess
        from unittest.mock import Mock
        from wormhole import ubuntu_recovery as recovery, rhel_hardening
        identifier=str(uuid4());name='wormhole-vm-'+identifier.replace('-','')[:12]
        result={'run_id':identifier,'source_revision':'a'*40,'provisioner':'terraform',
                'supervisor':{'pid':10},'build':{'capability':rhel_hardening.CAPABILITY}}
        lease=Mock()
        with patch.object(recovery.os,'geteuid',return_value=0),patch.object(recovery,'workspace_path',side_effect=lambda path:path), \
             patch.object(recovery,'read_json',return_value=result),patch.object(recovery,'sha256',return_value=recovery.vm.TF_SHA), \
             patch.object(recovery.vm,'process_identity',return_value=None),patch.object(recovery.VMLease,'resume',return_value=nullcontext(lease)), \
             patch.object(recovery.subprocess,'run',side_effect=[CompletedProcess([],1),RuntimeError('reached owned inspection')]) as inspect:
            lease.record={'resources':[{'kind':'support_container','identity':'other-services'}]}
            with self.assertRaises(RunError) as mismatch:recovery.recover(identifier,'fixture')
            self.assertEqual(mismatch.exception.code,'recovery_ownership_mismatch')
            inspect.assert_not_called()
            lease.record['resources'][0]['identity']=name+'-services'
            with self.assertRaisesRegex(RuntimeError,'reached owned inspection'):recovery.recover(identifier,'fixture')
            self.assertEqual(inspect.call_args.args[0],['docker','inspect',name+'-services'])

    def test_status_distinguishes_liveness_progress_and_lost_supervisor(self):
        import subprocess,sys
        from wormhole import vm_baseline as vm
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);identifier=str(uuid4());run=root/'vm-runs'/identifier;run.mkdir(parents=True,mode=0o700)
            value={'run_id':identifier,'source_revision':'a'*40,'outcome':'running','phase':'installing',
                   'cleanup':'pending','last_progress_at':'2020-01-01T00:00:00Z',
                   'supervisor':vm.process_identity(os.getpid())}
            atomic_json(run/'result.json',value)
            with patch.object(vm,'ROOT',root):
                self.assertEqual(vm.status(identifier)['execution_state'],'running-without-recent-progress')
                child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)'])
                try:value['supervisor']=vm.process_identity(child.pid)
                finally:child.terminate();child.wait(timeout=5)
                atomic_json(run/'result.json',value)
                observed=vm.status(identifier)
                self.assertEqual(observed['execution_state'],'unknown-supervisor-stopped')
                self.assertEqual(observed['outcome'],'running')
                self.assertEqual(json.loads((run/'result.json').read_text()),value)

    def test_console_key_frame_tolerates_boot_messages_but_rejects_ambiguity(self):
        from wormhole.vm_baseline import console_host_key
        start='WORMHOLE_FINAL_HOST_KEY_BEGIN\n'
        end='WORMHOLE_FINAL_HOST_KEY_END\n'
        body='[ OK ] Network ready\nssh-rsa AAAA fixture\n[ OK ] Audit started\n'
        self.assertIsNone(console_host_key(start+body,'ssh-rsa'))
        self.assertEqual(console_host_key(start+body+end,'ssh-rsa'),'ssh-rsa AAAA')
        with self.assertRaises(RunError) as error:
            console_host_key(start+body+'ssh-rsa BBBB other\n'+end,'ssh-rsa')
        self.assertEqual(error.exception.code,'guest_host_key_ambiguous')

    def test_confirmed_guest_panic_is_reported_at_boot_without_a_generic_timeout(self):
        from wormhole.vm_baseline import require_no_guest_panic
        require_no_guest_panic('diagnostic text mentioning Kernel panic - not syncing: audit')
        with self.assertRaises(RunError) as panic:
            require_no_guest_panic('[   11.125266] Kernel panic - not syncing: audit: backlog limit exceeded\n')
        self.assertEqual(panic.exception.code,'guest_audit_backlog_panic')

    def test_real_authentication_cannot_hide_failed_readiness_or_missing_dependents(self):
        from wormhole.vm_baseline import controller_checks,controller_failure,HELPER_CODE
        compile(HELPER_CODE,'<existing-vm-helper>','exec')
        rows=[{'stage':'final-authentication','returncode':0},
              {'stage':'final-system-readiness','returncode':42}]
        checks=controller_checks(rows,assessment=True)
        self.assertEqual(checks,{'final-authentication':'pass','final-system-readiness':'fail',
            'ansible-readiness':'blocked','functional':'blocked','inventory':'blocked','assessment-archive':'blocked'})
        self.assertEqual(controller_failure(rows),'final-system-readiness-failed')
        successful={'outcome':'baseline-passed','final_authentication':True}
        self.assertEqual(controller_failure([successful]),'controller-failed')
        self.assertEqual(controller_failure([successful,{'stage':'hardened-functional','returncode':1},
            {'stage':'assessment-archive','returncode':1}]),'hardened-functional-failed')
