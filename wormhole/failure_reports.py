"""Readable fault-experiment output from the same retained lifecycle records."""
from collections import Counter
from .runs import atomic_bytes, atomic_json


def report(record,lifecycle):
    targets=[]
    for target in lifecycle['targets'].values():
        counts=Counter(target['tests'].values());conditions=target['conditions']
        targets.append({'target_id':target['target_id'],'candidate_identity':lifecycle['candidate_identity'],
            'phase':target['current_phase'],'terminal_outcome':target['terminal_outcome'],
            'initialization_complete':conditions['initialization'],'configuration_complete':conditions['configuration'],
            'authentication_verified':conditions['final_identity'],'ansible_ready':all(conditions.values()) and
                not target['restart_pending'] and target['terminal_outcome'] not in {'failed','unknown','cancelled'},
            'tests_expected':len(target['tests']),'tests_passed':counts['pass'],
            'tests_failed':sum(counts[key] for key in ('fail','error','unreachable')),
            'tests_blocked':counts['blocked'],'tests_missing':counts['missing'],
            'first_failure':target['first_failure'],'last_progress_at':target['last_progress_at'],
            'evidence':['initialization.json','readiness.json','batch-validation.json','lifecycle.json']})
    created={event['target_id'] for event in lifecycle['events'] if event['event']=='created'}
    summary={'targets_expected':len(targets),'targets_created':len(created),
        'targets_initialized':sum(item['initialization_complete'] for item in targets),
        'targets_authenticated':sum(item['authentication_verified'] for item in targets),
        'targets_ansible_ready':sum(item['ansible_ready'] for item in targets),
        'targets_fully_tested':sum(item['tests_passed']+item['tests_failed']==item['tests_expected'] for item in targets)}
    for name in ('expected','passed','failed','blocked','missing'):
        summary['tests_'+name]=sum(item['tests_'+name] for item in targets)
    return {'operation':'failure-reproduction-report-v1','run_id':record['run_id'],
        'source_revision':record['source_revision'],'scenario':record['scenario'],'status':record['status'],
        'primary_failure':record['primary_failure'],'secondary_failures':record['secondary_failures'],
        'summary':summary,'targets':targets,'stage_timings':record['stage_timings'],
        'cleanup':record['cleanup'],'remote_state':lifecycle['remote_state'],
        'remaining_owned_resources':record['remaining_owned_resources'],
        'scenario_expectation_met':record['scenario_expectation_met'],
        'reference_eligible':False,'production_iso_eligible':False}


def target_text(value):
    return '\n'.join([value['target_id']+': '+value['phase']+' / '+value['terminal_outcome'],
        'Candidate: '+str(value['candidate_identity']),
        'Initialization/configuration/authentication/Ansible: '+' / '.join(str(value[key]) for key in
            ('initialization_complete','configuration_complete','authentication_verified','ansible_ready')),
        'Tests expected/passed/failed/blocked/missing: '+' / '.join(str(value['tests_'+key]) for key in
            ('expected','passed','failed','blocked','missing')),
        'First failure: '+str(value['first_failure']),'Evidence: '+', '.join(value['evidence'])])+'\n'


def write(run,record,lifecycle):
    value=report(record,lifecycle)
    atomic_json(run.file('evidence/failure-report.json'),value)
    lines=['Container failure reproduction: '+value['status'],
        'Expected negative observation: '+str(value['scenario_expectation_met']),
        'Reference eligibility: false. Production ISO eligibility: false.',
        'Summary: '+str(value['summary']),'Primary failure: '+str(value['primary_failure']),
        'Secondary failures: '+str(value['secondary_failures']),
        'Cleanup: '+str(value['cleanup']),'Stage timings: '+str(value['stage_timings'])]
    directory=run.file('evidence/targets');directory.mkdir(mode=0o700,exist_ok=True)
    for target in value['targets']:
        rendered=target_text(target);lines.append(rendered)
        atomic_bytes(directory/(target['target_id']+'.txt'),rendered.encode())
    atomic_bytes(run.file('evidence/failure-report.txt'),('\n'.join(lines)+'\n').encode())
    return value
