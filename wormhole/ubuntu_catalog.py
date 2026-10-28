"""Offline comparisons and a static local catalog of Ubuntu evidence."""
from collections import Counter
import html
import json
from pathlib import Path

from .runs import read_json,run_id
from .ubuntu_assessment import require


def load(run):
    run = Path(run)
    result = read_json(run / 'result.json')
    report = read_json(run / 'qualification.json')
    require(report['run_id'] == result['run_id'] and report['source_revision'] == result['source_revision']
            and report['candidate_sha256'] == result['build']['candidate_sha256'], 'report_attribution_mismatch')
    findings = json.loads((run / 'assessment/findings.json').read_text()) if (run / 'assessment/findings.json').exists() else {}
    svd = json.loads((run / 'installed-svd.json').read_text()) if (run / 'installed-svd.json').exists() else {}
    return result, report, findings, svd


def compare(previous, current, *, earlier=None):
    a, ar, af, av = load(previous);b, br, bf, bv = load(current)
    compatible = bool(af and bf and af['content_sha256'] == bf['content_sha256'] and af['profile_id'] == bf['profile_id']
                      and ar['policy_sha256']==br['policy_sha256'])
    left = {x['rule_id']:x['native_status'] for x in af.get('rules',[])}
    right = {x['rule_id']:x['native_status'] for x in bf.get('rules',[])}
    bad = {'fail','error','unknown','notchecked','missing','fixed'}
    good = {'pass','notapplicable'}
    trends = {'new':[], 'resolved':[], 'persistent':[], 'unevaluated':[], 'excluded':[],
              'reopened':None, 'reopened_note':'Requires a third attributable historical observation.'}
    if compatible:
        for key, status in right.items():
            old=left.get(key,'missing')
            if status in bad and old in good:trends['new'].append(key)
            if status in good and old in bad:trends['resolved'].append(key)
            if status in bad and old in bad:trends['persistent'].append(key)
            if status in {'missing','notchecked','unknown','error'}:trends['unevaluated'].append(key)
            if status=='notselected':trends['excluded'].append(key)
        if earlier is not None:
            _,_,ef,_=load(earlier)
            require(ef.get('content_sha256')==af['content_sha256'] and ef.get('profile_id')==af['profile_id'],
                    'trend_history_content_mismatch')
            first={x['rule_id']:x['native_status'] for x in ef['rules']}
            trends['reopened']=[key for key,status in right.items() if status in bad and left.get(key) in good and first.get(key) in bad]
            trends['reopened_note']='Three attributable compatible-content observations compared.'
    def packages(svd):return {(x['name'],x['architecture']):x['version'] for x in svd.get('packages',[])}
    pa,pb=packages(av),packages(bv)
    package_delta = {
        'available':bool(pa and pb),
        'added':[{'name':k[0],'architecture':k[1],'version':pb[k]} for k in sorted(pb.keys()-pa.keys())],
        'removed':[{'name':k[0],'architecture':k[1],'version':pa[k]} for k in sorted(pa.keys()-pb.keys())],
        'changed':[{'name':k[0],'architecture':k[1],'before':pa[k],'after':pb[k]} for k in sorted(pa.keys()&pb.keys()) if pa[k]!=pb[k]],
    }
    required_equal = (ar['functional_results'] and
        {r['id']:r['status'] for r in ar['functional_results']} == {r['id']:r['status'] for r in br['functional_results']})
    same_iso = ar['candidate_sha256'] == br['candidate_sha256']
    same_contract=a['build'].get('installed_input_fingerprint')==b['build'].get('installed_input_fingerprint')
    repeatable = (a['run_id'] != b['run_id'] and same_iso and same_contract and compatible and left==right and required_equal
                  and bool(pa) and pa==pb and av.get('kernel')==bv.get('kernel') and
                  av.get('inventory_complete') is True and bv.get('inventory_complete') is True and av.get('snaps')==bv.get('snaps') and
                  a.get('installed') is True and b.get('installed') is True and
                  a['cleanup']==b['cleanup']=='verified-absent-inputs-retained')
    old_inputs=a['build'].get('installed_inputs',{}).get('files',{})
    new_inputs=b['build'].get('installed_inputs',{}).get('files',{})
    input_changes=[{'input':key,'before':old_inputs.get(key),'after':new_inputs.get(key)}
                   for key in sorted(old_inputs.keys()|new_inputs.keys()) if old_inputs.get(key)!=new_inputs.get(key)]
    def snaps(svd):return {x['name']+':'+x['revision']:x for x in svd.get('snaps',[])}
    sa,sb=snaps(av),snaps(bv)
    return {'schema_version':'1.0','previous_run':a['run_id'],'current_run':b['run_id'],
        'same_tested_iso':same_iso,'assessment_comparable':compatible,'package_delta':package_delta,
        'snap_delta':{'added':[sb[k] for k in sorted(sb.keys()-sa.keys())],
                      'removed':[sa[k] for k in sorted(sa.keys()-sb.keys())],
                      'changed':[{'before':sa[k],'after':sb[k]} for k in sorted(sa.keys()&sb.keys()) if sa[k]!=sb[k]]},
        'installed_input_changes':input_changes,'same_installation_contract':same_contract,
        'policy_changed':ar['policy_sha256']!=br['policy_sha256'],
        'installed_inputs_changed':a['build'].get('installed_input_fingerprint')!=b['build'].get('installed_input_fingerprint'),
        'functional_changes':[{'id':r['id'],'before':next((x['status'] for x in ar['functional_results'] if x['id']==r['id']), 'missing'),'after':r['status']}
            for r in br['functional_results'] if not any(x['id']==r['id'] and x['status']==r['status'] for x in ar['functional_results'])],
        'findings_trends':trends if compatible else {'status':'incompatible-content; no security improvement conclusion'},
        'equivalent_fresh_installations':bool(repeatable),
        'normalization':'Compare required statuses, package name/version/architecture and running kernel. Unique host identities, secrets, boot IDs and timing remain in private evidence.',
        'lab_iso_qualified':False,'production_iso_eligible':False}


def catalog(root):
    root=Path(root);rows=[]
    for file in sorted(root.glob('*/qualification.json')):
        try:
            result,report,_,_=load(file.parent)
        except (ValueError,KeyError,OSError):
            continue
        identifier=run_id(result['run_id'])
        require(file.parent.name==identifier,'catalog_run_identity')
        rows.append({'run_id':identifier,'mode':report['mode'],'outcome':report['outcome'],
                     'lab_status':report['lab_status'],'candidate_sha256':report['candidate_sha256'],
                     'functional_counts':report['functional_counts'],'assessment':report['assessment'].get('selected_native_counts',{}),
                     'cleanup':report['cleanup']})
    def e(value):return html.escape(str(value),quote=True)
    body=[]
    for row in rows:
        body.append('<tr><td><a href="'+e(row['run_id'])+'/qualification.txt">'+e(row['run_id'])+'</a></td>'+
                    ''.join('<td>'+e(row[k])+'</td>' for k in ['mode','outcome','lab_status','functional_counts','assessment','cleanup'])+
                    '<td><code>'+e(row['candidate_sha256'])+'</code></td></tr>')
    page='''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Ubuntu lab evidence</title><style>
:root{color-scheme:light dark;font:15px/1.5 system-ui}body{margin:3rem auto;max-width:1500px;padding:0 1.5rem}
h1{font-size:1.8rem}table{border-collapse:collapse;width:100%;font-size:.85rem}th,td{text-align:left;vertical-align:top;padding:.7rem;border-bottom:1px solid #8885}
th{background:#8882}code{font-size:.75rem;overflow-wrap:anywhere}a{color:#3b82c5}.table{overflow:auto}</style>
<h1>Ubuntu lab evidence</h1><p>Installation, functional acceptance, assessment and qualification are separate outcomes.
Pending runs are not releases. Production eligibility is always false. Native private evidence stays in each run directory.</p>
<div class="table"><table><thead><tr><th>Run / report</th><th>Profile</th><th>Execution</th><th>Lab decision</th><th>Functional</th><th>Selected controls</th><th>Cleanup</th><th>Tested ISO SHA256</th></tr></thead><tbody>'''
    page+=''.join(body)+'</tbody></table></div></html>'
    (root/'catalog.html').write_text(page,encoding='utf-8')
    return rows
