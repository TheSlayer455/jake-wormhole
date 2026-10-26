"""Read-only checks for portable repository context and accidental runtime/secret files.

This baseline check is not a pipeline run or a comprehensive secret scanner.
"""
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    'AGENTS.md', 'README.md', 'docs/STATE.md', 'docs/TASKS.md',
    'docs/ARCHITECTURE.md', 'docs/FIDELITY.md', 'docs/DISCOVERY.md',
    'docs/REPOSITORY.md', 'docs/decisions/0001-container-reference.md',
    'handoff/CURRENT.md', 'handoff/reviews/README.md', 'prompts/CONTINUE.md',
    'prompts/REVIEW.md', 'scripts/verify_repository.py', '.github/workflows/verify.yml',
}
PRIVATE_KEY = re.compile(rb'-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----')
TOKEN = re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{60,})\b')
PRIVATE_ENDPOINT = re.compile(rb'https?://[^\s/()]+\.ts\.net(?=[:/\s)]|$)', re.I)
LINK = re.compile(r'(?<!!)\[[^\]]+\]\((<[^>]+>|[^\s)]+)(?:\s+"[^"]*")?\)')


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], stderr=subprocess.PIPE).decode().strip()


def verify():
    if sys.version_info < (3, 12):
        raise ValueError('Python 3.12 or newer is required')
    if Path(git('rev-parse', '--show-toplevel')).resolve() != ROOT:
        raise ValueError('Run the check inside the Wormhole checkout')
    origin = git('remote', 'get-url', 'origin')
    if not re.fullmatch(r'(?:https://github\.com/|git@github\.com:)TheSlayer455/jake-wormhole(?:\.git)?', origin, re.I):
        raise ValueError('The origin must identify the verified Jake Wormhole repository')
    tracked = {name for name in git('ls-files', '-z').split('\0') if name}
    errors = ['Missing tracked baseline file: ' + name for name in sorted(REQUIRED - tracked)]
    total = 0
    links = 0
    for name in sorted(tracked):
        relative = Path(name)
        target = ROOT / relative
        if not target.is_file() or target.is_symlink() or not target.resolve().is_relative_to(ROOT):
            errors.append('Tracked path is missing, linked or outside the checkout: ' + name)
            continue
        if relative.parts[0] in {'runs', 'state', 'private', '.wormhole', '.venv', '.terraform'} or \
                relative.name in {'.env', 'id_rsa', 'id_ed25519'} or \
                re.search(r'\.(?:sqlite(?:-wal|-shm)?|db|tfstate(?:\..*)?|tfplan|pem)$', name):
            errors.append('Mutable state or private material must stay outside Git: ' + name)
        size = target.stat().st_size
        total += size
        if size > 2 * 1024 * 1024 or total > 16 * 1024 * 1024:
            errors.append('Baseline source-size bound exceeded: ' + name)
            continue
        raw = target.read_bytes()
        if PRIVATE_KEY.search(raw) or TOKEN.search(raw):
            errors.append('Possible private key or known token format in: ' + name)
        if PRIVATE_ENDPOINT.search(raw):
            errors.append('Private runtime endpoint must remain outside public source: ' + name)
        if relative.suffix.lower() != '.md':
            continue
        for match in LINK.finditer(raw.decode('utf-8')):
            reference = urlsplit(match.group(1).strip('<>'))
            if reference.scheme or reference.netloc or not reference.path:
                continue
            linked = (target.parent / unquote(reference.path)).resolve()
            links += 1
            if not linked.is_relative_to(ROOT) or not linked.is_file() or linked.relative_to(ROOT).as_posix() not in tracked:
                errors.append('Missing or nonportable local link in: ' + name)
    return {
        'check': 'repository-baseline', 'passed': not errors,
        'source_revision': git('rev-parse', 'HEAD'), 'tracked_files': len(tracked),
        'working_tree_clean': not bool(git('status', '--porcelain')),
        'local_link_targets_checked': links, 'source_bytes': total, 'errors': errors,
        'runtime_pipeline_tested': False, 'comprehensive_secret_scan': False,
    }


if __name__ == '__main__':
    try:
        report = verify()
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        report = {'check': 'repository-baseline', 'passed': False,
                  'errors': ['Repository check could not complete; inspect the checkout and required tools.']}
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['passed'] else 1)
