"""One auditable check correction; no selections, requirements or results change.

The upstream mapper object omits the vendor grammar's terminating semicolon.
Accept only the required pwent value in a complete, uncommented assignment.
Preserve and assess the original data stream independently.
"""
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from .runs import RunError, atomic_json
from .vm_inputs import sha256

UPSTREAM_SHA='18a09c7dc5d05d8c10ca89f0514014da322d4f0430ca6f66b69e71b02fddb12a'
OBJECT='oval:ssg-obj_verify_use_mappers:obj:1'
PATTERN=r'^[ \t]*use_mappers[ \t]*=[ \t]*pwent[ \t]*;[ \t]*$'


def derive(source,destination):
    source,destination=Path(source),Path(destination)
    if sha256(source)!=UPSTREAM_SHA or destination.exists():
        raise RunError('content_erratum_inputs','Use the exact pinned original and a new output path.')
    raw=source.read_bytes();root=ET.fromstring(raw)
    objects=[e for e in root.iter() if e.get('id')==OBJECT]
    if len(objects)!=1:raise RunError('content_erratum_object','Expected one mapper object.')
    patterns=[e for e in objects[0] if e.tag.rsplit('}',1)[-1]=='pattern']
    if len(patterns)!=1 or 'use_mappers = pwent' not in (patterns[0].text or ''):
        raise RunError('content_erratum_pattern','Expected the pinned original mapper pattern.')
    before=patterns[0].text
    span=rb'(<(?:[A-Za-z0-9_]+:)?pattern\b[^>]*>)'+re.escape(before.encode())+rb'(</(?:[A-Za-z0-9_]+:)?pattern>)'
    if len(re.findall(span,raw))!=1:raise RunError('content_erratum_ambiguous','Expected one exact pattern span.')
    updated=re.sub(span,lambda m:m[1]+PATTERN.encode()+m[2],raw)
    # Only this pattern span changes. Preserve every other source byte, including
    # all rules, references, selections, severities, remediation and profile IDs.
    destination.write_bytes(updated)
    return {'schema_version':'1.0','id':'pwent-vendor-grammar-1','upstream_sha256':UPSTREAM_SHA,
            'derived_sha256':sha256(destination),'object_id':OBJECT,'before':before,'after':PATTERN,
            'rule_id':'xccdf_org.ssgproject.content_rule_verify_use_mappers',
            'requirement':'UBTU-22-612040','rule_selection_unchanged':True,
            'upstream_native_assessment_required':True,
            'basis':'https://opensc.github.io/pam_pkcs11/doc/mappers_api.html'}
