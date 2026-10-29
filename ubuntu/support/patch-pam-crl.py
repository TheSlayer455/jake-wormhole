"""Narrow OpenSSL object-access repair for the pinned Ubuntu PAM source.

No validation is disabled: retain CA, signature, OCSP and CRL checks. Build input
archives are authenticated by Ubuntu's signed snapshot before this runs inside
the isolated builder. The receipt binds both source-file identities.
"""
import difflib
import hashlib
import json
from pathlib import Path


def repair(text):
    before=text
    for target,function in [('issuer_cert','X509_OBJECT_get0_X509'),
                            ('crl','X509_OBJECT_get0_X509_CRL'),('x509_ca','X509_OBJECT_get0_X509')]:
        old=target+' = '+function+'((&obj));'
        if text.count(old)!=1:raise ValueError('unexpected pinned OpenSSL accessor source')
        new=('#if OPENSSL_VERSION_NUMBER >= 0x10100000L\n'
             '    '+target+' = '+function+'(obj);\n'
             '#else\n    '+target+' = '+function+'(&obj);\n#endif')
        if target=='crl':
            new+=('\n    /* Own a CRL reference after the lookup object is freed. */\n'
                  '    if (crl != NULL) {\n'
                  '#if OPENSSL_VERSION_NUMBER >= 0x10100000L\n'
                  '      if (X509_CRL_up_ref(crl) != 1) crl = NULL;\n'
                  '#else\n      CRYPTO_add(&crl->references, 1, CRYPTO_LOCK_X509_CRL);\n#endif\n    }')
        text=text.replace(old,new,1)
    text=text.replace('pkey = X509_get_pubkey(issuer_cert);','pkey = issuer_cert ? X509_get_pubkey(issuer_cert) : NULL;',1)
    text=text.replace('dist_points = X509_get_ext_d2i(x509_ca, NID_crl_distribution_points, NULL, NULL);',
                      'dist_points = x509_ca ? X509_get_ext_d2i(x509_ca, NID_crl_distribution_points, NULL, NULL) : NULL;',1)
    needle='  rv = verify_crl(crl, ctx);'
    if text.count(needle)!=1:raise ValueError('unexpected CRL verification source')
    text=text.replace(needle,'  if (crl == NULL) {\n    set_error("CRL lookup returned no object");\n    return -1;\n  }\n'+needle,1)
    needle='  } else if (rv == 0) {\n    return 0;\n  }\n  DBG("checking revocation");'
    if text.count(needle)!=1:raise ValueError('unexpected CRL failure cleanup source')
    text=text.replace(needle,'  } else if (rv == 0) {\n    X509_CRL_free(crl);\n    return 0;\n  }\n  DBG("checking revocation");',1)
    if text==before:raise ValueError('no repair applied')
    return text


if __name__=='__main__':
    path=Path('src/common/cert_vfy.c')
    before=path.read_bytes();after=repair(before.decode()).encode()
    Path('wormhole-pam-crl.patch').write_text(''.join(difflib.unified_diff(before.decode().splitlines(True),
        after.decode().splitlines(True),fromfile='a/src/common/cert_vfy.c',tofile='b/src/common/cert_vfy.c')))
    path.write_bytes(after)
    Path('wormhole-pam-repair.json').write_text(json.dumps({'id':'openssl-object-and-crl-ownership-1',
        'before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':hashlib.sha256(after).hexdigest(),
        'revocation_checks_retained':True,'supported_runtime_test':'Ubuntu 22.04 / OpenSSL 3'},sort_keys=True))
