"""Original reference software payload, not an operating-system/ISO validator."""
VERSION = '1.0.0-reference'


def describe(configuration, source_sha256):
    if configuration != {'format': 'wormhole-reference-v1', 'greeting': 'reference-ready'}:
        raise ValueError('Fixed reference configuration required')
    if type(source_sha256) is not str or len(source_sha256) != 64:
        raise ValueError('Source digest required')
    return {'version': VERSION, 'message': configuration['greeting'], 'source_sha256': source_sha256}
