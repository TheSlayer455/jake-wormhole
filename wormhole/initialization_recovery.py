"""Proof that one lost operation was a contained initialization exec.

Unknown creates, Terraform calls and commits remain blocked. The original known
provider receipt, unchanged inputs/operations, exact target/start and canonical
recovery lease precede the existing read/stop adapter.
"""
from copy import deepcopy
import hashlib
import re

from . import images
from .initialization import RECORD,SOURCE,require
from .recovery import valid_failure
from .runs import common,read_json,source_identity
from .targets import TargetPlan


class InitializationProof:
    def __init__(self,run,lease):
        lease._active();manifest=run.manifest()
        require(run.workspace==images.RUNS_ROOT and lease._reconciliation_only is True and
            lease.run_id==run.id and lease.source_revision==manifest['source_revision'] and
            lease.plan['synthetic'] is False and source_identity()==(manifest['source_revision'],False),
            'initialization_recovery_scope')
        record=read_json(run.file(RECORD))
        require(common(record)==common(manifest) and record.get('operation')=='owned-container-initialization-v1' and
            record.get('source_sha256')==hashlib.sha256(SOURCE.read_bytes()).hexdigest() and
            record.get('unknown_outcome') is True and record.get('production_iso_eligible') is False and
            type(record.get('attempts')) is list and 1<=len(record['attempts'])<=80,'initialization_recovery_scope')
        plan=TargetPlan.from_lease(lease)
        require(record['expected_targets']==list(plan.target_ids),'initialization_recovery_scope')
        index=len(record['attempts'])-1;attempt=record['attempts'][index]
        require(attempt['target_id'] in plan.target_ids and type(attempt['resource_id']) is str and
            re.fullmatch('[a-f0-9]{64}',attempt['resource_id']) and type(attempt['started_at']) is str and
            attempt.get('provider_before')=='private/initialization-provider-before-'+str(index).zfill(3)+'.json',
            'initialization_recovery_scope')
        path=run.file(attempt['provider_before']);before=read_json(path)
        with path.open('rb') as stream:raw=stream.read(262145)
        require(len(raw)<=262144 and hashlib.sha256(raw).hexdigest()==attempt.get('provider_before_sha256'),
            'initialization_provider_proof_changed')
        require(common(before)==common(manifest) and before.get('unknown_outcome') is False and
            before.get('target_plan')==plan.record() and before.get('operation')=='terraform-smoke' and
            before.get('scenario')=='healthy','initialization_provider_proof_changed')
        targets={row['address']:row['id'] for row in before['resources']}
        require(targets.get(plan.address_for(attempt['target_id']))==attempt['resource_id'],'initialization_recovery_scope')
        self.run,self.lease,self.record,self.before=run,lease,deepcopy(record),deepcopy(before)
        self.target_id=attempt['target_id'];self.allowed_pending=set()
        context_path=run.file('private/readiness-controller.json')
        if context_path.exists():
            from .readiness import readiness_status
            helper=readiness_status(run);context=read_json(context_path);identifier=context.get('helper_id')
            require(context.get('run_id')==run.id and context.get('source_revision')==manifest['source_revision'] and
                context.get('unknown_outcome') is False and helper['unknown_outcome'] is False and
                helper.get('helper_id')==identifier and (identifier is None or type(identifier) is str and
                    re.fullmatch('[a-f0-9]{64}',identifier)),'initialization_helper_unknown')
            if identifier is not None:self.allowed_pending.add(('container',identifier))

    def validate(self,run,lease,current):
        require(run is self.run and lease is self.lease,'initialization_recovery_scope')
        before=self.before;mutable={'updated_at','unknown_outcome','primary_failure','secondary_failures','status'}
        require(type(current) is dict and set(current)==set(before) and
            {key:value for key,value in current.items() if key not in mutable}==
            {key:value for key,value in before.items() if key not in mutable} and
            current['status'] in {before['status'],'failed'} and type(current['unknown_outcome']) is bool and
            valid_failure(current['primary_failure']) and valid_failure(before['primary_failure']) and
            (before['primary_failure'] is None or current['primary_failure']==before['primary_failure']) and
            type(current['secondary_failures']) is list and len(current['secondary_failures'])<=64 and
            current['secondary_failures'][:len(before['secondary_failures'])]==before['secondary_failures'] and
            all(valid_failure(item) for item in current['secondary_failures']),
            'initialization_provider_state_changed')
        return True
