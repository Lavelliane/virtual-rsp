#!/usr/bin/env python3
import os
import sys
import base64
import json
import secrets
from pathlib import Path
import requests

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def load_cert(path: Path) -> x509.Certificate:
    with open(path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read())


def load_key(path: Path):
    with open(path, 'rb') as f:
        return load_pem_private_key(f.read(), password=None)


def build_euicc_info1(ci_cert: x509.Certificate) -> bytes:
    # Minimal EUICCInfo1: [2]=SVN 2.2.1, [9]=SEQUENCE OF (ci SKI), [10]=SEQUENCE OF (ci SKI)
    #  BF20 len  82 03 02 02 01  A9 16 04 14 <20b SKI>  AA 16 04 14 <20b SKI>
    ski_ext = ci_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    ski = ski_ext.key_identifier
    if len(ski) != 20:
        raise ValueError('CI SKI must be 20 bytes for v2 flow')
    body = bytearray()
    # [2] SVN 2.2.1
    body += bytes([0x82, 0x03, 0x02, 0x02, 0x01])
    # [9] euiccCiPKIdListForVerification ::= SEQUENCE OF OCTET STRING, implicit [9]
    elem = bytes([0x04, 0x14]) + ski
    body += bytes([0xA9]) + asn1_len(elem) + elem
    # [10] euiccCiPKIdListForSigning ::= SEQUENCE OF OCTET STRING, implicit [10]
    body += bytes([0xAA]) + asn1_len(elem) + elem
    # wrap with BF20
    out = bytearray([0xBF, 0x20, len(body)])
    out += body
    return bytes(out)


def asn1_len(b: bytes) -> bytes:
    L = len(b)
    if L < 0x80:
        return bytes([L])
    s = L.to_bytes((L.bit_length()+7)//8, 'big')
    return bytes([0x80 | len(s)]) + s


def build_euicc_signed1(transaction_id: bytes, server_address: str, server_challenge: bytes, euicc_svn=(2,2,1)) -> bytes:
    # euiccSigned1 ::= SEQUENCE { transactionId [0], serverAddress [3], serverChallenge [4], euiccInfo2 [34], ctxParams1 }
    seq = bytearray()
    # [0] transactionId (OCTET STRING implicit)
    seq += bytes([0x80]) + asn1_len(transaction_id) + transaction_id
    # [3] serverAddress (UTF8String implicit)
    sa = server_address.encode('utf-8')
    seq += bytes([0x83]) + asn1_len(sa) + sa
    # [4] serverChallenge (OCTET STRING)
    seq += bytes([0x84]) + asn1_len(server_challenge) + server_challenge
    # [34] EUICCInfo2 with SVN and profileVersion (minimal)
    info2_content = bytearray()
    # [2] svn 
    info2_content += bytes([0x82, 0x03, euicc_svn[0], euicc_svn[1], euicc_svn[2]])
    # [1] profileVersion - tag 81 according to SGP.22 spec
    info2_content += bytes([0x81, 0x01, 0x01])
    seq += bytes([0xBF, 0x22]) + asn1_len(info2_content) + info2_content
    # ctxParams1 minimal
    seq += bytes([0x30, 0x02, 0x01, 0x00])
    return bytes([0x30]) + asn1_len(seq) + seq


def tr03111_from_der(der_sig: bytes) -> bytes:
    # Convert DER ECDSA signature to raw r||s
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(der_sig)
    r_b = r.to_bytes(32, 'big')
    s_b = s.to_bytes(32, 'big')
    return r_b + s_b


def main():
    root = Path(__file__).resolve().parents[1]
    # Add pySIM to path to use its ASN.1 compiler
    sys.path.insert(0, str(root.parent / 'pysim'))
    from pySim.esim import rsp
    v_cert_dir = root / 'certs'
    pysim_cert_dir = root.parent / 'pysim' / 'smdpp-data' / 'certs' / 'DPtls'

    # Determine CI PKID matching DPauth AKI used by SM-DP+
    common_certs = root.parent / 'pysim' / 'smdpp-data' / 'certs'
    dp_auth_derpath = common_certs / 'DPauth' / 'CERT_S_SM_DPauth_ECDSA_NIST.der'
    dp_auth = x509.load_der_x509_certificate(dp_auth_derpath.read_bytes())
    dp_aki = dp_auth.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
    # Find CI with SKI == dp_auth AKI
    ci_dir = common_certs / 'CertificateIssuer'
    ci_cert = None
    for p in ci_dir.iterdir():
        if p.suffix.lower() in ('.der', '.pem'):
            try:
                cert = x509.load_der_x509_certificate(p.read_bytes()) if p.suffix.lower()=='.der' else load_cert(p)
                ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.key_identifier
                if ski == dp_aki:
                    ci_cert = cert
                    break
            except Exception:
                continue
    if ci_cert is None:
        raise RuntimeError('Unable to find CI certificate matching DPauth AKI')
    eum_cert = load_cert(v_cert_dir / 'eum_cert.pem')
    euicc_cert = load_cert(v_cert_dir / 'euicc_cert.pem')
    euicc_key = load_key(v_cert_dir / 'euicc_key.pem')

    euicc_info1 = build_euicc_info1(ci_cert)
    euicc_info1_b64 = base64.b64encode(euicc_info1).decode('ascii')
    euicc_challenge = secrets.token_bytes(16)

    base_url = f'https://testsmdpplus1.example.com:8443'
    # Use the certificate chain bundle that includes both TLS cert and CI cert
    verify_path = str(root / 'tls_chain.pem')

    # ES9+ InitiateAuthentication
    init_payload = {
        'smdpAddress': 'testsmdpplus1.example.com',
        'euiccChallenge': base64.b64encode(euicc_challenge).decode('ascii'),
        'euiccInfo1': euicc_info1_b64,
    }
    r = requests.post(f'{base_url}/gsma/rsp2/es9plus/initiateAuthentication', json=init_payload, verify=verify_path, timeout=10)
    r.raise_for_status()
    init_js = r.json()
    hdr = init_js['header']['functionExecutionStatus']
    assert hdr['status'] == 'Executed-Success', hdr
    serverSigned1_b64 = init_js['serverSigned1']
    serverSignature1_b64 = init_js['serverSignature1']
    transactionId = init_js['transactionId']
    serverCert_der = base64.b64decode(init_js['serverCertificate'])
    server_addr = 'testsmdpplus1.example.com'
    serverSigned1 = base64.b64decode(serverSigned1_b64)
    serverSignature1 = base64.b64decode(serverSignature1_b64)
    # Extract serverChallenge (tag 0x84, length 16) from serverSigned1
    srv_chal = None
    i = 0
    while i+2 <= len(serverSigned1):
        if serverSigned1[i] == 0x84 and (i+2) <= len(serverSigned1):
            l = serverSigned1[i+1]
            if l == 16 and (i+2+l) <= len(serverSigned1):
                srv_chal = serverSigned1[i+2:i+2+l]
                break
        i += 1
    if srv_chal is None:
        raise RuntimeError('serverChallenge not found in serverSigned1')

    # Build euiccSigned1 using pySIM structures to ensure all required fields
    from cryptography.hazmat.primitives.asymmetric import ec
    
    print("Building euiccSigned1 using pySIM ASN.1 structures...")
    euicc_signed1_struct = {
        'transactionId': bytes.fromhex(transactionId),
        'serverAddress': server_addr,
        'serverChallenge': srv_chal,
        'euiccInfo2': {
            'profileVersion': b'\x01',  # minimal version
            'svn': b'\x02\x02\x01',     # SVN 2.2.1
            'euiccFirmwareVer': b'\x01\x00\x00',  # minimal firmware version
            'extCardResource': b'\x00\x00\x00\x00'  # minimal resource info
        },
        'ctxParams1': ('ctxParamsForCommonAuthentication', b'\x00')  # CHOICE structure for common auth
    }
    
    euicc_signed1 = rsp.asn1.encode('EuiccSigned1', euicc_signed1_struct)
    print(f"EuiccSigned1 encoded: {len(euicc_signed1)} bytes")
    
    der_sig = euicc_key.sign(euicc_signed1, ec.ECDSA(hashes.SHA256()))
    euicc_sig_tr = tr03111_from_der(der_sig)

    # Use pySIM to properly encode AuthenticateServerResponse
    euicc_der = euicc_cert.public_bytes(encoding=Encoding.DER)
    eum_der = eum_cert.public_bytes(encoding=Encoding.DER)
    
    print("Building AuthenticateServerResponse using pySIM ASN.1 compiler...")
    
    # Use the structure we already built for pySIM encoding
    auth_resp_dec = (
        'authenticateResponseOk',
        {
            'euiccSigned1': euicc_signed1_struct,
            'euiccSignature1': euicc_sig_tr,
            'euiccCertificate': rsp.asn1.decode('Certificate', euicc_der),
            'eumCertificate': rsp.asn1.decode('Certificate', eum_der),
        }
    )
    auth_resp_bin = rsp.asn1.encode('AuthenticateServerResponse', auth_resp_dec)
    euicc_auth_b64 = base64.b64encode(auth_resp_bin).decode('ascii')
    
    print(f"AuthenticateServerResponse encoded successfully: {len(auth_resp_bin)} bytes")
    
    # Verify we can decode it back
    verify_decode = rsp.asn1.decode('AuthenticateServerResponse', auth_resp_bin)
    print(f"Verification decode: {verify_decode[0]}")

    # ES9+ AuthenticateClient
    auth_client_payload = {
        'transactionId': transactionId,
        'authenticateServerResponse': euicc_auth_b64,
    }
    r2 = requests.post(f'{base_url}/gsma/rsp2/es9plus/authenticateClient', json=auth_client_payload, verify=verify_path, timeout=15)
    r2.raise_for_status()
    print('AuthenticateClient OK:', r2.json()['header']['functionExecutionStatus']['status'])

    print('Auth flow completed successfully')


if __name__ == '__main__':
    sys.exit(main())


