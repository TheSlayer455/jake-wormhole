"""Explain profile boundaries without treating upstream notselected as a pass."""
import re


def reconcile(rows,baseline,target):
    """Compare operator-supplied authoritative manual benchmarks, without
    copying their check text or treating identifier coverage as equivalence.
    """
    from .ubuntu_assessment import digest,require,xml
    def read(path):
        root=xml(path).getroot();ns=root.tag.rsplit('}',1)[0]+'}'
        release=root.find(ns+'plain-text[@id="release-info"]')
        require(release is not None and release.text,'manual_benchmark_identity_missing')
        rules={}
        for row in root.iter(ns+'Rule'):
            identifier=row.findtext(ns+'version')
            require(isinstance(identifier,str) and re.fullmatch(r'UBTU-22-\d+',identifier) and identifier not in rules,
                    'manual_benchmark_rule_invalid')
            rules[identifier]={'check':row.findtext(ns+'check/'+ns+'check-content'),
                'fix':row.findtext(ns+'fixtext'),'severity':row.get('severity')}
        require(rules,'manual_benchmark_empty')
        return {'sha256':digest(path),'version':root.findtext(ns+'version'),'release':release.text},rules
    old,a=read(baseline);new,b=read(target)
    mapping={key:[] for key in b}
    for row in summarize(rows)['rules']:
        for key in row['ubuntu_stig_ids']:
            if key in mapping:mapping[key].append({k:row[k] for k in ('rule_id','upstream_selected','native_status')})
    changed=[]
    for key in sorted(set(a)&set(b)):
        fields=[field for field in ('check','fix','severity') if a[key][field]!=b[key][field]]
        if fields:changed.append({'control':key,'changed_fields':fields,'mapped_rules':mapping[key]})
    return {'schema_version':'1.0','baseline':old,'target':new,'target_controls':len(b),
        'added_controls':sorted(set(b)-set(a)),'removed_controls':sorted(set(a)-set(b)),
        'changed_controls':changed,'unmapped_controls':[k for k,v in mapping.items() if not v],
        'controls':mapping,'evidence_category':'actual source-content comparison; not a guest assessment',
        'manual_revision_mapping_complete':all(mapping.values()),'usg_execution_proven':False,
        'scanner_logic_equivalence_established':False,'production_iso_eligible':False}


def summarize(rows):
    mappings=[]
    for row in rows:
        identifiers=sorted({ref['value'] for ref in row.get('references',[])
                            if isinstance(ref.get('value'),str) and re.fullmatch(r'UBTU-22-\d+',ref['value'])})
        mappings.append({'rule_id':row['rule_id'],'upstream_selected':row['selected'],
                         'ubuntu_stig_ids':identifiers,'native_status':row['native_status']})
    return {'content_distribution':'ComplianceAsCode 0.1.82 Ubuntu V2R7',
        'intended_usg_revision':'V2R8',
        'revision_mapping':'not established; authoritative V2R8 rule/content comparison remains required',
        'notselected_meaning':'Outside the selected upstream profile; neither pass nor fail and not an engineer exclusion',
        'selected_rules':sum(r['upstream_selected'] for r in mappings),
        'upstream_notselected_rules':sum(not r['upstream_selected'] for r in mappings),
        'unselected_with_ubuntu_stig_ids':[r['rule_id'] for r in mappings if not r['upstream_selected'] and r['ubuntu_stig_ids']],
        'rules':mappings,'usg_equivalence_established':False}
