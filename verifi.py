from collections import OrderedDict
from dateutil.parser import parse as parse_datetime
from OpenSSL import SSL, crypto
import certifi
import datetime
import re
import socket
import sys

DEFAULT_PORT = 443

OPENSSL_ERRORS = {
    2: 'Unable to get issuer cert',
    3: 'Unable to get CRL',
    4: 'Unable to decrypt cert signature',
    5: 'Unable to decrypt CRL signature',
    6: 'Unable to decode issuer public key',
    7: 'Cert signature failed',
    8: 'CRL signature failed',
    9: 'Cert not yet valid',
    10: 'Cert has expired',
    11: 'CRL not yet valid',
    12: 'CRL has expired',
    13: 'Error in cert not before field',
    14: 'Error in cert not after field',
    15: 'Error in CRL last update field',
    16: 'Error in CRL next update field',
    17: 'Out of memory',
    18: 'Depth zero self-signed cert',
    19: 'Self-signed cert in chain',
    20: 'Unable to get issuer cert locally',
    21: 'Unable to verify leaf signature',
    22: 'Cert chain too long',
    23: 'Cert revoked',
    24: 'Invalid certificate authority',
    25: 'Path length exceeded',
    26: 'Invalid purpose',
    27: 'Cert untrusted',
    28: 'Cert rejected',
    29: 'Subject issuer mismatch',
    30: 'AKID SKID mistmatch',
    31: 'AKID issuer serial mismatch',
    32: 'KeyUsage no certSign',
    33: 'Unable to get CRL issuer',
    34: 'Unhandled critical extension',
    35: 'KeyUsage no CRL sign',
    36: 'Unhandled critical CRL extension',
    37: 'Invalid non CA',
    38: 'Proxy path length exceeded',
    39: 'KeyUsage no digital signature',
    40: 'Proxy certificates not allowed',
    41: 'Invalid extension',
    42: 'Invalid policy extension',
    43: 'No explicit policy',
    44: 'Different CRL scope',
    45: 'Unsupported extension feature',
    46: 'Unnested resource',
    47: 'Permitted violation',
    48: 'Excluded violation',
    49: 'Subtree min/max',
    50: 'Application verification',
    51: 'Unsupported constraint type',
    52: 'Unsupported constraint syntax',
    53: 'Unsupported name syntax',
    54: 'CRL path validation error',
}


class CertificateChain(object):

    def __init__(self):
        self.certs = OrderedDict()

    def add_cert(self, cert):
        self.certs[cert.digest] = cert

    @property
    def root(self):
        if self.certs:
            return self.certs.values()[0]

    @property
    def leaf(self):
        if self.certs:
            return next(reversed(self.certs.values()))
        

class Name(object):

    def __init__(self, components):
        self.components = components

    def __getitem__(self, key):
        for comp in self.components:
            if comp[0] == key:
                return comp[1]

    def __str__(self):
        return '/%s' % '/'.join('%s=%s' % (k, v) for k, v in self.components)


class Certificate(object):

    @classmethod
    def from_x509(cls, x509):
        c = cls()
        c.digest = x509.digest('md5')
        c.pem = crypto.dump_certificate(crypto.FILETYPE_PEM, x509)
        c.expiration_date = parse_datetime(x509.get_notAfter())
        c.subject = Name(x509.get_subject().get_components())
        c.issuer = Name(x509.get_issuer().get_components())
        return c


class VerificationError(Exception):
    
    def __init__(self, message, cert):
        self.cert = cert
        super(VerificationError, self).__init__(message)


class Verifier(object):

    def __init__(self, hostname, port=DEFAULT_PORT):
        self.hostname = hostname
        self.port = port
        self.ip = socket.gethostbyname(hostname)
        self.errors = []
        self.certs = CertificateChain()

    def add_error(self, cert, message):
        err = VerificationError(message, cert)
        self.errors.append(err)

    def reset(self):
        self.errors = []
        self.certs = CertificateChain()

    def verify(self):

        self.reset()

        def verify_callback(conn, x509, errno, depth, result):
            cert = Certificate.from_x509(x509)
            self.certs.add_cert(cert)
            if errno:
                message = OPENSSL_ERRORS.get(errno)
                if message:
                    self.add_error(cert, message)
            return result
        
        context = SSL.Context(SSL.TLSv1_METHOD)
        context.set_options(SSL.OP_NO_SSLv2)
        context.set_verify(SSL.VERIFY_NONE, verify_callback)
        context.load_verify_locations(certifi.where())

        client = SSL.Connection(context, socket.socket())
        client.set_connect_state()
        client.set_tlsext_host_name(self.hostname)
        client.connect((self.ip, self.port))
        client.do_handshake()
        client.close()

        leaf_cert = self.certs.leaf
        common_name = leaf_cert.subject['CN']

        if common_name.lower() != self.hostname.lower():
            self.add_error(leaf_cert, 'Hostname does not match')


def verify(hostname, port=DEFAULT_PORT):
    v = Verifier(hostname)
    v.verify()
    return v.errors


#
# CLI entry point
#

def main():
    
    import argparse

    status_code = 0
    
    parser = argparse.ArgumentParser(description='Verify TLS certificate chain.')
    parser.add_argument('hostname', metavar='HOSTNAME', type=str, help='site to verify')
    parser.add_argument('-p', '--port', dest='port', metavar='PORT', type=int,
                default=DEFAULT_PORT, help='host port (default: %s)' % DEFAULT_PORT)

    args = parser.parse_args()

    sys.stdout.write('Verifying certs at %s\n' % args.hostname)

    v = Verifier(args.hostname, args.port)
    v.verify()

    if v.errors:
        sys.stdout.write('Found the following issues:\n')
        for err in v.errors:
            sys.stdout.write('- %s [%s]\n' % (err.message, err.cert.subject['CN']))
        sys.stdout.write('FAILED!\n') 
        status_code = 1
    else:
        sys.stdout.write('OK!\n') 

    sys.exit(status_code)

if __name__ == '__main__':
    main()
    