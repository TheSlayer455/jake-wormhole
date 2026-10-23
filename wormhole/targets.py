"""Bounded deterministic target identities, separate from observed resources.

This describes a reviewed layout; it does not reserve or allocate anything.
Twenty-target plans remain planning-only until the separate runtime ticket.
"""
from dataclasses import dataclass
import json

from .runs import RunError

LAYOUT = 'indexed-targets-v1'
COUNTS = {'smoke': 1, 'five-targets': 5, 'twenty-targets': 20}
NETWORK = 'docker_network.run'


class TargetPlanError(RunError):
    pass


@dataclass(frozen=True)
class TargetPlan:
    profile: str

    def __post_init__(self):
        if type(self.profile) is not str or self.profile not in COUNTS:
            raise TargetPlanError('target_plan_invalid', 'Use an exact supported reviewed target profile.')

    @property
    def target_ids(self):
        return tuple('target-' + str(i).zfill(3) for i in range(1, COUNTS[self.profile] + 1))

    @property
    def expected_addresses(self):
        return frozenset((NETWORK, *(self.address_for(identifier) for identifier in self.target_ids)))

    def address_for(self, target_id):
        if type(target_id) is not str or target_id not in self.target_ids:
            raise TargetPlanError('target_identity_invalid', 'Target identity is outside the exact admitted plan.')
        return 'docker_container.target[' + json.dumps(target_id) + ']'

    def id_for_address(self, address):
        matches = [identifier for identifier in self.target_ids if self.address_for(identifier) == address]
        if type(address) is not str or len(matches) != 1:
            raise TargetPlanError('target_identity_invalid', 'Resource address is outside the exact admitted plan.')
        return matches[0]

    def resolve(self, target_id=None):
        if target_id is None and len(self.target_ids) == 1:
            return self.target_ids[0]
        self.address_for(target_id)
        return target_id

    def record(self):
        return {'schema_version': '1.0', 'resource_layout': LAYOUT, 'profile': self.profile,
                'target_count': len(self.target_ids), 'target_ids': list(self.target_ids)}

    @classmethod
    def from_record(cls, value):
        if type(value) is not dict:
            raise TargetPlanError('target_plan_invalid', 'A complete immutable target plan is required.')
        result = cls(value.get('profile'))
        if type(value.get('target_count')) is not int or value != result.record():
            raise TargetPlanError('target_plan_invalid', 'Target plan layout or identities changed.')
        return result

    @classmethod
    def from_lease(cls, lease):
        lease._active()
        if type(lease.plan) is not dict:
            raise TargetPlanError('target_plan_invalid', 'A complete immutable admission plan is required.')
        result = cls(lease.plan.get('profile'))
        if type(lease.plan.get('target_count')) is not int or lease.plan['target_count'] != len(result.target_ids):
            raise TargetPlanError('target_plan_invalid', 'Target count differs from the reviewed profile.')
        return result
