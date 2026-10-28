"""Two declared lab configuration values; never rule exclusions or waivers."""
import xml.etree.ElementTree as ET

PROFILE='xccdf_org.wormhole_profile_ubuntu_lab_stig'
VALUES={'var_audispd_remote_server':'192.0.2.1',
        'remote_login_banner_text':r'^Wormhole private home lab\. Authorized lab use only\. Activity is monitored\.$'}


def validate(policy):
    from .ubuntu_assessment import require
    tailoring=policy.get('tailoring',{'excluded_rules':[],'parameters':{},'owner_approved_exceptions':[]})
    parameters=tailoring.get('parameters')
    require(set(tailoring)=={'excluded_rules','parameters','owner_approved_exceptions'} and
        tailoring['excluded_rules']==[] and tailoring['owner_approved_exceptions']==[] and
        parameters in ({},VALUES),'unsupported_assessment_tailoring')
    return parameters


def profile(policy):
    return PROFILE if validate(policy) else policy['content']['profile_id']


def document(policy):
    parameters=validate(policy)
    if not parameters:return None
    x='{http://checklists.nist.gov/xccdf/1.2}'
    root=ET.Element(x+'Tailoring',id='xccdf_org.wormhole_tailoring_ubuntu_lab')
    ET.SubElement(root,x+'benchmark',href='ssg-ubuntu2204-ds.xml')
    ET.SubElement(root,x+'version',time='2026-10-28T00:00:00Z').text='1'
    p=ET.SubElement(root,x+'Profile',id=PROFILE,extends=policy['content']['profile_id'])
    ET.SubElement(p,x+'title').text='Wormhole lab endpoint and truthful lab notice'
    ET.SubElement(p,x+'description').text='Unchanged upstream rule selection; only the declared audit receiver and home-lab banner values differ.'
    for key,value in sorted(parameters.items()):ET.SubElement(p,x+'set-value',idref='xccdf_org.ssgproject.content_value_'+key).text=value
    return ET.tostring(root,encoding='utf-8',xml_declaration=True)
