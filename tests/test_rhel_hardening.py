"""Generated-input regressions; real fresh KVM execution remains separate."""
from pathlib import Path
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from uuid import uuid4

from wormhole import rhel_hardening as h, rhel_inputs as baseline
from wormhole.runs import RunError


class HardenedInputs(unittest.TestCase):
    def seed(self, **changes):
        args = {'identifier': str(uuid4()), 'public_key': 'ssh-rsa ' + 'A' * 544,
            'guest_address': '192.0.2.10/24', 'mac': '52:54:00:11:22:33',
            'password_hash': '$6$synthetic$' + 'A' * 86,
            'boot_hash': 'grub.pbkdf2.sha512.10000.' + 'A' * 128 + '.' + 'B' * 128}
        return h.kickstart(**{**args, **changes})

    def test_installer_fips_and_seed_keep_secrets_out_of_media_and_preserve_baseline(self):
        original = "search --no-floppy --set=root -l '" + baseline.LABEL + "'\n"
        kernel = ' linux /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=' + baseline.LABEL
        boot = h.boot_config(original + kernel + '\n' + kernel + ' inst.rescue\n')
        self.assertIn(kernel + ' inst.rescue\n', boot)
        self.assertEqual(boot.count('fips=1'), 1)
        self.assertEqual(boot.count('inst.notmux'), 1)
        self.assertNotIn('inst.notmux',baseline.boot_config(original + kernel + '\n'))
        self.assertIn('inst.ks=hd:LABEL=WORMHOLEKS:/ks.cfg', boot)
        self.assertNotIn('fips=1', baseline.boot_config(original + kernel + '\n'))
        seed = self.seed()
        self.assertIn('rootpw --lock', seed)
        self.assertIn('--iscrypted --password=grub.pbkdf2', seed)
        self.assertNotIn('NOPASSWD', h.FINALIZE)
        self.assertIn('%wheel ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL', h.FINALIZE)
        self.assertNotIn('PRIVATE KEY', seed)
        for changes in ({'public_key': 'ssh-ed25519 ' + 'A' * 68},
                        {'password_hash': 'plaintext'}, {'boot_hash': 'plaintext'}):
            with self.assertRaises(RunError): self.seed(**changes)

    def test_pre_storage_include_uses_console_receiver_and_encrypted_swap(self):
        seed = self.seed()
        script = seed.split("/usr/bin/python3 <<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        compile(script, '<installer-secret-receiver>', 'exec')
        self.assertIn('%pre --interpreter=/bin/bash --erroronfail', seed)
        self.assertIn('%include /run/wormhole-storage.ks', seed)
        self.assertIn('WORMHOLE_INSTALL_UNLOCK_REQUEST', script)
        self.assertIn('quiet[3]&=~termios.ECHO', script)
        self.assertIn("os.chmod('/run/wormhole-storage.ks',0o600)", script)
        layout = h.STORAGE.format(secret='synthetic-test-value')
        self.assertEqual(len(re.findall(r'^part ', layout, re.M)), 3)
        self.assertIn('--luks-version=luks2 --pbkdf=pbkdf2', layout)
        self.assertIn('logvol swap --vgname=system', layout)
        self.assertNotIn('part swap', layout)

    @unittest.skipUnless(shutil.which('bash'), 'Bash parser required for installed shell syntax')
    def test_generated_shell_scripts_parse_and_readiness_follows_hardening_and_reboot(self):
        scripts = [h.FINALIZE, h.READY]
        scripts += re.findall(r'^%(?:pre|post|onerror)[^\n]*\n(.*?)^%end$', self.seed(), re.M | re.S)
        for script in scripts:
            result = subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('0|2)', h.FINALIZE)
        self.assertIn('exit "$result"', h.FINALIZE)
        self.assertNotIn('WORMHOLE_FINAL_HOST_KEY_BEGIN', h.FINALIZE)
        self.assertIn('installation-boot-id)" !=', h.READY)
        self.assertIn('ssh_host_rsa_key.pub', h.READY)
        self.assertLess(h.READY.index('getenforce'), h.READY.index('installation-complete'))
        self.assertIn('Requires=wormhole-ready.service', h.FINALIZE)
        self.assertIn('After=local-fs.target sshd-keygen.target', h.FINALIZE)
        self.assertIn('StreamDriverAuthMode="x509/name"', h.FINALIZE)
        self.assertNotIn('update-ca-trust', h.FINALIZE)
        installer=self.seed().split('%post --nochroot',1)[1].split('%end',1)[0]
        self.assertNotIn('\ninstall ',installer) # RHEL10 stage2 omits coreutils install.
        self.assertIn('chmod 0644 /mnt/sysroot/etc/wormhole-lab-ca.crt',installer)

    def test_final_chrony_configuration_preserves_client_only_controls_after_remediation(self):
        chrony = h.FINALIZE.split("cat > /etc/chrony.conf <<'TIME'\n", 1)[1].split('\nTIME\n', 1)[0]
        self.assertIn('server 192.0.2.1 port 12345 iburst minpoll 4 maxpoll 4', chrony)
        self.assertEqual(chrony.splitlines().count('port 0'), 1)
        self.assertEqual(chrony.splitlines().count('cmdport 0'), 1)
        self.assertLess(h.FINALIZE.index('oscap xccdf eval --remediate'),
                        h.FINALIZE.index("cat > /etc/chrony.conf <<'TIME'"))

    def test_final_name_resolution_uses_the_declared_local_only_path(self):
        self.assertIn("cat > /etc/NetworkManager/conf.d/90-wormhole-dns.conf <<'DNS'", h.FINALIZE)
        self.assertIn('dns=none', h.FINALIZE)
        self.assertIn('$i != "dns"', h.FINALIZE)
        self.assertIn('install -m 0644 /dev/null /etc/resolv.conf', h.FINALIZE)
        self.assertIn("NetworkManager --print-config | grep -qx 'dns=none'", h.READY)
        self.assertIn('test ! -s /etc/resolv.conf', h.READY)

    def test_final_banner_uses_the_pinned_rule_path_after_remediation(self):
        self.assertIn("> /etc/issue\n", h.FINALIZE)
        self.assertIn("'Banner /etc/issue' > /etc/ssh/sshd_config.d/05-wormhole-banner.conf", h.FINALIZE)
        self.assertNotIn('Banner /etc/issue.net', h.FINALIZE)
        tailoring = h.tailoring_document().decode()
        self.assertIn('id="' + h.LAB_PROFILE + '"', tailoring)
        self.assertIn('content_value_login_banner_text', tailoring)
        self.assertIn('content_value_var_accounts_authorized_local_users_regex', tailoring)
        self.assertIn(h.LAB_AUTHORIZED_USERS_REGEX, tailoring)
        self.assertNotIn(':select', tailoring)

    def test_final_kdump_unit_is_disabled_and_masked_after_remediation(self):
        self.assertIn('services --disabled=debug-shell,autofs,kdump', self.seed())
        self.assertLess(h.FINALIZE.index('oscap xccdf eval --remediate'),
                        h.FINALIZE.index('systemctl mask kdump.service'))

    def test_final_grub_admin_changes_the_generator_and_rebuilds_the_config(self):
        generator = r'''if [ -f \${prefix}/user.cfg ]; then
  source \${prefix}/user.cfg
  if [ -n "\${GRUB2_PASSWORD}" ]; then
    set superusers="root"
    export superusers
    password_pbkdf2 root \${GRUB2_PASSWORD}
  fi
fi
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '01_users'
            path.write_text(generator)
            start = h.FINALIZE.index('sed -Ei \\\n', h.FINALIZE.index("test -s /etc/grub.d/01_users"))
            end = h.FINALIZE.index('/etc/grub.d/01_users', start) + len('/etc/grub.d/01_users')
            transform = h.FINALIZE[start:end].replace('/etc/grub.d/01_users', str(path))
            result = subprocess.run(['bash'], input='set -eu\n' + transform + '\n',
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            changed = path.read_text()
        self.assertIn('set superusers="wormhole_boot_admin"', changed)
        self.assertIn(r'password_pbkdf2 wormhole_boot_admin \${GRUB2_PASSWORD}', changed)
        self.assertNotIn('password_pbkdf2 root ', changed)
        self.assertIn("grep -Eq '^GRUB2_PASSWORD=grub\\.pbkdf2\\.' /boot/grub2/user.cfg", h.FINALIZE)
        self.assertIn('grub2-mkconfig -o /boot/grub2/grub.cfg', h.FINALIZE)
        self.assertIn('! getent passwd wormhole_boot_admin', h.READY)

    def test_final_admin_uses_passworded_selinux_role_transition(self):
        self.assertLess(h.FINALIZE.index('oscap xccdf eval --remediate'),
                        h.FINALIZE.index('usermod -Z staff_u lab.service'))
        self.assertIn('%wheel ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL', h.FINALIZE)
        self.assertIn('Defaults:lab.service timestamp_timeout=0', h.FINALIZE)
        self.assertIn('visudo -c', h.FINALIZE)
        self.assertNotIn('lab.service ALL=(ALL) ALL', h.FINALIZE)
        self.assertNotIn('NOPASSWD', h.FINALIZE)
        self.assertIn('$2 != "staff_u"', h.READY)

    def test_reuse_binds_installed_recipe_and_refuses_baseline_or_modified_bytes(self):
        manifest = {'capability': h.CAPABILITY, 'source': baseline.RHEL,
                    'candidate_sha256': 'a' * 64, 'installed_input_fingerprint': 'b' * 64}
        h.verify_reuse(manifest, 'a' * 64, 'b' * 64)
        for changes in ({'capability': baseline.CAPABILITY}, {'source': {'release': '9'}},
                        {'candidate_sha256': 'c' * 64}, {'installed_input_fingerprint': 'c' * 64}):
            with self.assertRaises(RunError): h.verify_reuse({**manifest, **changes}, 'a' * 64, 'b' * 64)
        self.assertNotIn('lab_iso_qualified', h.installation_contract())

    @unittest.skipUnless(shutil.which('bash'), 'Actual Bash ERR semantics required')
    def test_wrong_installed_os_stops_before_later_readiness_checks(self):
        identity=h.READY.split('. /etc/os-release\n',1)[1].split('findmnt ',1)[0]
        for distro,version in (('ubuntu','10.0'),('rhel','9.0'),('rhel','10.0')):
            script='set -eu\nID='+distro+'\nVERSION_ID='+version+'\n'+identity+'echo CONTINUE\n'
            result=subprocess.run(['bash'],input=script,text=True,capture_output=True)
            self.assertEqual(result.returncode==0,(distro,version)==('rhel','10.0'))
            self.assertEqual(result.stdout,'CONTINUE\n' if result.returncode==0 else '')

    @unittest.skipUnless(shutil.which('bash'), 'Actual Bash ERR semantics required')
    def test_native_findings_do_not_emit_installer_failure_but_scanner_error_does(self):
        block=h.FINALIZE.split('if timeout ',1)[1].split('test -s ',1)[0].replace('/dev/ttyS0','/dev/stdout')
        for code in (0,2,3):
            script="set -euo pipefail\ntrap 'echo INSTALLER_FAILED' ERR\ntimeout(){ return "+str(code)+"; }\nif timeout "+block+"\necho CONTINUE\n"
            result=subprocess.run(['bash'],input=script,text=True,capture_output=True)
            if code in (0,2):
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stdout,'CONTINUE\n')
            else:
                self.assertEqual(result.returncode,3)
                self.assertEqual(result.stdout,'WORMHOLE_INSTALLATION_FAILED\n')

    def test_wrong_content_is_rejected_before_any_build_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); content = root / 'datastream.xml'; content.write_text('wrong content')
            with self.assertRaises(RunError) as error: h.prepare(content)
            self.assertEqual(error.exception.code, 'rhel_content_identity_mismatch')
            self.assertEqual(list(root.iterdir()), [content])

    def test_frozen_lab_policy_retains_native_coverage_and_unverified_dependencies(self):
        policy = json.loads((Path(__file__).resolve().parents[1] / 'profiles/rhel10-lab-policy-v1.json').read_text())
        self.assertEqual(policy['policy_id'], h.installation_contract()['qualification_policy'])
        self.assertEqual(policy['content']['datastream_sha256'], h.CONTENT_SHA256)
        self.assertEqual(policy['content']['profile_id'], h.PROFILE)
        self.assertEqual(policy['content']['upstream_rules'], h.CONTENT['rules'])
        self.assertEqual(policy['content']['selected_rules'], h.CONTENT['selected_rules'])
        self.assertEqual(h.installation_contract()['policy_sha256'], h.sha256(h.POLICY))
        self.assertFalse(policy['production_iso_eligible'])
        self.assertEqual(policy['tailoring'], {'excluded_rules': [],
            'parameters': {'login_banner_text': h.LAB_BANNER_REGEX,
                'var_accounts_authorized_local_users_regex': h.LAB_AUTHORIZED_USERS_REGEX,
                'var_networkmanager_dns_mode': 'none'},
            'owner_approved_exceptions': []})
        self.assertEqual(policy['requirements']['independent_same_iso_installations'], 2)
        self.assertTrue(policy['unresolved_requirements'])
        self.assertIn('approved-evaluate-stig-package-and-supported-rhel10-execution', policy['external_work_equivalence_pending'])
        self.assertNotIn('approved-evaluate-stig-package-and-supported-rhel10-execution', policy['unresolved_requirements'])
