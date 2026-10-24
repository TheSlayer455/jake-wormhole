"""Fixed private worker dispatch; no arbitrary commands, roots or PID adoption."""
import sys
from .isolation_acceptance import worker
from .recovery import safe_code


def main(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    try:
        if len(arguments) != 3:
            raise ValueError('Fixed role, suite UUID and target UUID required.')
        worker(*arguments)
        return 0
    except Exception as error:
        import json
        print(json.dumps({'error': {'code': safe_code(error)}, 'private_evidence_retained': True}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
