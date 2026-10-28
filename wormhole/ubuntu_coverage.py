"""Explain profile boundaries without treating upstream notselected as a pass."""
import re


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
