"""Extract reviewed rule blocks from the pinned upstream Bash content."""
import json
from pathlib import Path
import re
import subprocess

from .runs import SOURCE_ROOT
from .ubuntu_assessment import inventory, require
from .vm_inputs import sha256

PLAN = SOURCE_ROOT / 'ubuntu/remediation-plan-v1.json'


def generate(store, payload):
    plan = json.loads(PLAN.read_text())
    source = Path(store) / 'ubuntu2204-script-stig.sh'
    require(sha256(source) == plan['upstream_script_sha256'], 'remediation_content_mismatch')
    blocks = re.findall(
        r"# BEGIN fix \(\d+ / \d+\) for 'xccdf_org.ssgproject.content_rule_([^']+)'(.*?)# END fix for 'xccdf_org.ssgproject.content_rule_\1'",
        source.read_text(), re.S)
    require(len(blocks) == 230 and len(dict(blocks)) == 230, 'remediation_rule_inventory')
    available = dict(blocks)
    wanted = plan['remediation_rules']
    require(len(set(wanted)) == len(wanted) and set(wanted) <= set(available), 'remediation_selection')
    assessed = inventory(Path(store) / 'ssg-ubuntu2204-ds.xml')
    require(all(assessed['xccdf_org.ssgproject.content_rule_' + r]['selected'] for r in wanted),
            'remediation_unselected_rule')
    scripts = Path(payload) / 'remediation';scripts.mkdir(mode=0o700)
    for name in wanted:
        require('FIX FOR THIS RULE' not in available[name], 'upstream_remediation_unavailable')
        (scripts / (name + '.sh')).write_text(available[name])
        subprocess.run(['bash', '-n', str(scripts / (name + '.sh'))], check=True, timeout=5)
    (Path(payload) / 'remediation-plan.json').write_text(json.dumps(plan, sort_keys=True))
    return plan
