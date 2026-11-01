"""Explain profile boundaries without treating upstream notselected as a pass."""
import re

V2R7_SHA = 'edbe8221f0a4bd791c05df5a2230813dc9b87cd0da7a94eab700485cc56a8804'
V2R8_SHA = '73c26b6592dfc02f7f0eb456e0f89143ea1e2d8af7ebc61bd8bfae01f5a4c9d8'
V2R8_CHANGES = {**{key:['fix'] for key in ('UBTU-22-232080','UBTU-22-232085',
    'UBTU-22-232090','UBTU-22-232095','UBTU-22-271030')},
    'UBTU-22-251020':['check','fix'], 'UBTU-22-255020':['check','fix']}
V2R8_PROBES = {'UBTU-22-251020':'v2r8-ufw-effective-status',
              'UBTU-22-255020':'v2r8-banner-effective-file'}


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
                'fix':row.findtext(ns+'fixtext'),'severity':row.get('severity'),
                'title':row.findtext(ns+'title'),'description':row.findtext(ns+'description')}
        require(rules,'manual_benchmark_empty')
        return {'sha256':digest(path),'version':root.findtext(ns+'version'),'release':release.text},rules
    old,a=read(baseline);new,b=read(target)
    mapping={key:[] for key in b}
    for row in summarize(rows)['rules']:
        for key in row['ubuntu_stig_ids']:
            if key in mapping:mapping[key].append({k:row[k] for k in ('rule_id','upstream_selected','native_status')})
    changed=[];text_changed=[]
    for key in sorted(set(a)&set(b)):
        fields=[field for field in ('check','fix','severity') if a[key][field]!=b[key][field]]
        if fields:changed.append({'control':key,'changed_fields':fields,'mapped_rules':mapping[key]})
        fields=[field for field in ('title','description') if a[key][field]!=b[key][field]]
        if fields:text_changed.append({'control':key,'changed_fields':fields})
    return {'schema_version':'1.0','baseline':old,'target':new,'target_controls':len(b),
        'added_controls':sorted(set(b)-set(a)),'removed_controls':sorted(set(a)-set(b)),
        'changed_controls':changed,'text_changed_controls':text_changed,
        'unmapped_controls':[k for k,v in mapping.items() if not v],
        'controls':mapping,'evidence_category':'actual source-content comparison; not a guest assessment',
        'manual_revision_mapping_complete':all(mapping.values()),'usg_execution_proven':False,
        'scanner_logic_equivalence_established':False,'production_iso_eligible':False}


def reviewed_v2r8(value, functional_results):
    """Close only the pinned manual revision delta, not USG or ISO qualification.

    The caller binds the reconciliation and functional observations to the run.
    Native findings for unchanged controls remain subject to the assessment gate.
    """
    try:
        if (value['baseline']['sha256']!=V2R7_SHA or value['target']['sha256']!=V2R8_SHA
                or value['target_controls']!=188 or value['manual_revision_mapping_complete'] is not True
                or value['added_controls'] or value['removed_controls'] or value['unmapped_controls']
                or value['text_changed_controls']):return False
        controls=value['controls'];changes=value['changed_controls']
        if (len(controls)!=188 or any(not re.fullmatch(r'UBTU-22-\d+',key) or not rows
                for key,rows in controls.items()) or len(changes)!=len(V2R8_CHANGES)
                or {r['control']:r['changed_fields'] for r in changes}!=V2R8_CHANGES):return False
        for row in changes:
            mapped=controls[row['control']]
            if row['mapped_rules']!=mapped:return False
            if row['control'] not in V2R8_PROBES and not all(
                    r['upstream_selected'] is True and r['native_status'] in {'pass','notapplicable'}
                    for r in mapped):return False
        probes=[r for r in functional_results if r['id'] in V2R8_PROBES.values()]
        return len(probes)==2 and {r['id']:r['status'] for r in probes}=={
            key:'pass' for key in V2R8_PROBES.values()}
    except (KeyError,TypeError,AttributeError):return False


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
