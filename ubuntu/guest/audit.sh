#!/bin/bash
# Assessment only. Remediation is a separate installation payload.
set -euo pipefail
test "$(id -u)" = 0
. /etc/os-release
test "$ID:$VERSION_ID" = ubuntu:22.04
test "$(systemd-detect-virt)" = kvm || test "$(systemd-detect-virt)" = qemu
test -s /var/lib/wormhole/run-id
test -f /var/lib/wormhole/installation-complete
test "$(cat /var/lib/wormhole/final-boot-id)" = "$(cat /proc/sys/kernel/random/boot_id)"
test "$(cat /var/lib/wormhole/firstboot-id)" != "$(cat /var/lib/wormhole/final-boot-id)"
install -d -m 0700 /var/lib/wormhole/assessment
cd /var/lib/wormhole/assessment
test ! -e scanner-receipt.json
cp /var/lib/wormhole/finalization.log ./finalization.log
if test -f /var/lib/wormhole/remediation-results.json; then
  cp /var/lib/wormhole/remediation-results.json ./remediation-results.json
fi
oscap --version > scanner-version.txt
if test -f /usr/local/lib/wormhole/toolchain.json; then
  # Focused side-by-side diagnostic of the observed old partition-probe result.
  # Keep its native outcome separate; it cannot substitute for the full new scan.
  set +e
  timeout 60 /usr/bin/oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig \
    --rule xccdf_org.ssgproject.content_rule_encrypt_partitions --results legacy-encryption.xml \
    /usr/local/lib/wormhole/ssg-ubuntu2204-ds.xml > legacy-encryption.log 2>&1
  legacy_exit=$?
  set -e
  printf '%s\n' "$legacy_exit" > legacy-encryption-exit.txt
fi
date --utc --iso-8601=seconds > started-at.txt
profile=xccdf_org.ssgproject.content_profile_stig
tailoring=()
if test -f /usr/local/lib/wormhole/lab-tailoring.xml; then
  # Preserve a full native upstream observation alongside the declared lab
  # endpoint/banner values. Neither profile removes or deselects any rule.
  set +e
  timeout 600 oscap xccdf eval --profile "$profile" --results upstream-xccdf.xml \
    /usr/local/lib/wormhole/ssg-ubuntu2204-ds.xml > upstream-scanner.log 2>&1
  upstream_exit=$?
  set -e
  printf '%s\n' "$upstream_exit" > upstream-exit.txt
  test "$upstream_exit" = 0 || test "$upstream_exit" = 2
  profile=xccdf_org.wormhole_profile_ubuntu_lab_stig
  tailoring=(--tailoring-file /usr/local/lib/wormhole/lab-tailoring.xml)
fi
set +e
timeout --signal=TERM --kill-after=10 600 oscap xccdf eval \
 --profile "$profile" "${tailoring[@]}" \
 --results xccdf.xml --results-arf arf.xml --report report.html \
 /usr/local/lib/wormhole/ssg-ubuntu2204-ds.xml > scanner.log 2>&1
scanner_exit=$?
set -e
printf '%s\n' "$scanner_exit" > scanner-exit.txt
python3 - <<'PY'
import hashlib,json,pathlib,platform,datetime
r=pathlib.Path('/var/lib/wormhole')
value={'schema_version':'1.0','run_id':(r/'run-id').read_text().strip(),
 'target':platform.node(),'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
 'firstboot_id':(r/'firstboot-id').read_text().strip(),
 'content_sha256':hashlib.sha256(pathlib.Path('/usr/local/lib/wormhole/ssg-ubuntu2204-ds.xml').read_bytes()).hexdigest(),
 'scanner_exit':int((r/'assessment/scanner-exit.txt').read_text()),
 'started_at':(r/'assessment/started-at.txt').read_text().strip(),
 'completed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'remediation_during_assessment':False}
tailoring=pathlib.Path('/usr/local/lib/wormhole/lab-tailoring.xml')
value['tailoring_sha256']=hashlib.sha256(tailoring.read_bytes()).hexdigest() if tailoring.exists() else None
(r/'assessment/scanner-receipt.json').write_text(json.dumps(value,sort_keys=True))
PY
# The real scanner exit remains in the receipt. Collection is possible on failure.
exit 0
