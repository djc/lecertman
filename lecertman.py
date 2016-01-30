#!/usr/bin/env python
from __future__ import print_function

from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat import backends
from cryptography.x509 import oid
from cryptography import x509

import json, os, base64, binascii, time, hashlib, re, copy, textwrap, sys

try:
    from urllib.request import urlopen # Python 3
except ImportError:
    from urllib2 import urlopen # Python 2

#CA = 'https://acme-staging.api.letsencrypt.org'
CA = "https://acme-v01.api.letsencrypt.org"
AGREEMENT = 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf'
WELL_KNOWN_URL = 'http://%s/.well-known/acme-challenge/%s'

def int_to_bytes(n):
    h = hex(n)[2:].rstrip('L')
    return binascii.unhexlify(('0' + h) if len(h) % 2 else h)

def b64(b):
    return base64.urlsafe_b64encode(b).decode('utf8').replace('=', '')

def send_signed_request(ca, url, key, header, payload):

    payload64 = b64(json.dumps(payload).encode('utf-8'))
    protected = copy.deepcopy(header)
    protected['nonce'] = urlopen(ca + '/directory').headers['Replay-Nonce']
    protected64 = b64(json.dumps(protected).encode('utf8'))

    signer = key.signer(PKCS1v15(), hashes.SHA256())
    signer.update(('%s.%s' % (protected64, payload64)).encode('utf-8'))
    signature = b64(signer.finalize())

    data = json.dumps({
        'header': header, 'protected': protected64,
        'payload': payload64, 'signature': signature,
    })
    try:
        resp = urlopen(url, data.encode('utf8'))
        return resp.getcode(), resp.read()
    except IOError as e:
        return getattr(e, 'code', None), getattr(e, 'read', e.__str__)()

def register(ca, priv_key, header):
    url = ca + '/acme/new-reg'
    code, result = send_signed_request(ca, url, priv_key, header, {
        'resource': 'new-reg', 'agreement': AGREEMENT,
    })

def get_certificate(account_key, domains):

    # Read private key from file

    backend = backends.default_backend()
    with open(account_key, 'rb') as f:
        priv_key = serialization.load_pem_private_key(f.read(), None, backend)

    # Create JWS header

    pub_key = priv_key.public_key()
    key_n = int_to_bytes(pub_key.public_numbers().n)
    key_e = int_to_bytes(pub_key.public_numbers().e)
    header = {
        'alg': 'RS256',
        'jwk': {
            'kty': 'RSA',
            'e': b64(int_to_bytes(pub_key.public_numbers().e)),
            'n': b64(int_to_bytes(pub_key.public_numbers().n)),
        },
    }
    key_json = json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))
    thumbprint = b64(hashlib.sha256(key_json.encode('utf8')).digest())

    # Create certificate key

    print('Creating certificate key... ', end='')
    cert_key = rsa.generate_private_key(65537, 4096, backend)
    with open(domains[0][0] + '.key', 'wb') as f:
        f.write(cert_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    print('done')

    # Create CSR

    attrs = [
        (oid.NameOID.COUNTRY_NAME, u'NL'),
        (oid.NameOID.STATE_OR_PROVINCE_NAME, u'NH'),
        (oid.NameOID.LOCALITY_NAME, u'Amsterdam'),
        (oid.NameOID.ORGANIZATION_NAME, u'XavaMedia Web Services'),
    ]
    attrs.append((oid.NameOID.COMMON_NAME, domains[0][0]))
    attrs = x509.Name([x509.NameAttribute(i[0], i[1]) for i in attrs])
    csr = x509.CertificateSigningRequestBuilder().subject_name(attrs)

    if len(domains) > 1:
        names = [x509.DNSName(d[0]) for d in domains[1:]]
        ext = x509.SubjectAlternativeName(names)
        csr = builder.add_extension(ext, critical=False)

    csr = csr.sign(cert_key, hashes.SHA256(), backend)

    # Verify domains

    for domain, challenge_dir in domains:

        print('Verifying %s domain... ' % domain, end='')
        url = CA + '/acme/new-authz'
        code, result = send_signed_request(CA, url, priv_key, header, {
            'resource': 'new-authz',
            'identifier': {'type': 'dns', 'value': domain},
        })
        if code != 201:
            msg = 'Error requesting challenges: {0} {1}'
            raise ValueError(msg.format(code, result))

        # Write challenge response to file

        rsp = json.loads(result.decode('utf-8'))
        challenge = [c for c in rsp['challenges'] if c['type'] == 'http-01'][0]
        token = re.sub(r'[^A-Za-z0-9_\-]', '_', challenge['token'])
        key_authz = '%s.%s' % (token, thumbprint)
        well_known_path = os.path.join(challenge_dir, token)
        with open(well_known_path, 'w') as f:
            f.write(key_authz)

        # Check that the response file is in place

        well_known_url = WELL_KNOWN_URL % (domain, token)
        try:
            rsp = urlopen(well_known_url)
            data = rsp.read().decode('utf8').strip()
            assert data == key_authz
        except (IOError, AssertionError):
            os.remove(well_known_path)
            msg = "Wrote file to %s, but couldn't download %s"
            raise ValueError(msg % (well_known_path, well_known_url))

        # Send challenge response

        payload = {'resource': 'challenge', 'keyAuthorization': key_authz}
        bits = CA, challenge['uri'], priv_key, header, payload
        code, result = send_signed_request(*bits)
        if code != 202:
            msg = 'Error triggering challenge: %s %s'
            raise ValueError(msg % (code, result))

        # Wait for challenge response to be verified
        while True:

            try:
                rsp = urlopen(challenge['uri'])
                status = json.loads(rsp.read().decode('utf8'))
            except IOError as e:
                bits = e.code, json.loads(e.read().decode('utf-8'))
                raise ValueError('Error checking challenge: %s %s' % bits)

            if status['status'] == 'pending':
                time.sleep(2)
            elif status['status'] == 'valid':
                os.remove(well_known_path)
                break
            else:
                msg = '%s challenge did not pass: %s'
                raise ValueError(msg % (domain, status))

        print('done')

    # Get the new certificate

    print('Retrieving certificate... ', end='')
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    cert_req = {'resource': 'new-cert', 'csr': b64(csr_der)}
    bits = CA, CA + '/acme/new-cert', priv_key, header, cert_req
    code, result = send_signed_request(*bits)
    if code != 201:
        raise ValueError('Error signing certificate: %s %s' % (code, result))
    print('done')

    # Write certificate to disk

    pem_cert = base64.b64encode(result).decode('utf-8')
    with open(domains[0][0] + '.crt', 'w') as f:
        f.write('-----BEGIN CERTIFICATE-----\n')
        f.write('\n'.join(textwrap.wrap(pem_cert, 64)))
        f.write('\n-----END CERTIFICATE-----\n')

if __name__ == "__main__":
    key_file, domain, challenge_dir = sys.argv[1], sys.argv[2], sys.argv[3]
    get_certificate(key_file, [(domain.decode('utf-8'), challenge_dir)])
