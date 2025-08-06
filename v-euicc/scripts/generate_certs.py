#!/usr/bin/env python3
"""
Generate ECDSA certificates for virtual eUICC compatible with SGP.22 standards.
This script creates eUICC and EUM certificates that chain properly to the CI certificates.
"""

import os
import sys
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import ipaddress
import secrets

def generate_eid():
    """Generate a random 32-character hex EID"""
    return secrets.token_hex(16).upper()

def generate_private_key():
    """Generate ECDSA private key using P-256 curve"""
    return ec.generate_private_key(ec.SECP256R1())

def load_ci_cert(cert_path):
    """Load Certificate Issuer certificate"""
    with open(cert_path, 'rb') as f:
        return x509.load_der_x509_certificate(f.read())

def create_eum_certificate(ci_cert, ci_private_key, eid, output_dir):
    """Create EUM (eUICC Manufacturer) certificate"""
    # Generate EUM private key
    eum_private_key = generate_private_key()
    
    # Create EUM certificate
    eum_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Virtual eUICC Manufacturer"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Virtual eUICC Division"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Virtual EUM Certificate"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, f"EUM{eid[:16]}"),
    ])
    
    # Certificate validity
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=3650)  # 10 years
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(eum_subject)
    builder = builder.issuer_name(ci_cert.subject)
    builder = builder.public_key(eum_private_key.public_key())
    builder = builder.serial_number(int.from_bytes(os.urandom(16), byteorder="big"))
    builder = builder.not_valid_before(valid_from)
    builder = builder.not_valid_after(valid_to)
    
    # Add extensions
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(eum_private_key.public_key()),
        critical=False,
    )
    
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ci_cert.public_key()),
        critical=False,
    )
    
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    )
    
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            content_commitment=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    
    # Add Certificate Policy for EUM (SGP.22 compliant)
    builder = builder.add_extension(
        x509.CertificatePolicies([
            x509.PolicyInformation(
                policy_identifier=x509.ObjectIdentifier("2.23.146.1.2.1.2"),  # EUM policy OID
                policy_qualifiers=None,
            ),
        ]),
        critical=False,
    )
    
    # Sign the certificate
    eum_cert = builder.sign(ci_private_key, hashes.SHA256())
    
    # Save EUM certificate and private key
    eum_cert_path = output_dir / "eum_cert.pem"
    eum_key_path = output_dir / "eum_key.pem"
    
    with open(eum_cert_path, "wb") as f:
        f.write(eum_cert.public_bytes(serialization.Encoding.PEM))
    
    with open(eum_key_path, "wb") as f:
        f.write(eum_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print(f"EUM certificate written to: {eum_cert_path}")
    print(f"EUM private key written to: {eum_key_path}")
    
    return eum_cert, eum_private_key

def create_euicc_certificate(eum_cert, eum_private_key, eid, output_dir):
    """Create eUICC certificate"""
    # Generate eUICC private key
    euicc_private_key = generate_private_key()
    
    # Create eUICC certificate
    euicc_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Virtual eUICC"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Virtual eUICC Unit"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Virtual eUICC Certificate"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, eid),  # EID as serial number
    ])
    
    # Certificate validity
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=3650)  # 10 years
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(euicc_subject)
    builder = builder.issuer_name(eum_cert.subject)
    builder = builder.public_key(euicc_private_key.public_key())
    builder = builder.serial_number(int.from_bytes(os.urandom(16), byteorder="big"))
    builder = builder.not_valid_before(valid_from)
    builder = builder.not_valid_after(valid_to)
    
    # Add extensions
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(euicc_private_key.public_key()),
        critical=False,
    )
    
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(eum_cert.public_key()),
        critical=False,
    )
    
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=False,
            crl_sign=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            content_commitment=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    
    # Add Extended Key Usage for eUICC
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.ObjectIdentifier("1.3.6.1.4.1.31136.1.1.1.1"),  # eUICC authentication
        ]),
        critical=False,
    )
    
    # Sign the certificate
    euicc_cert = builder.sign(eum_private_key, hashes.SHA256())
    
    # Save eUICC certificate and private key
    euicc_cert_path = output_dir / "euicc_cert.pem"
    euicc_key_path = output_dir / "euicc_key.pem"
    
    with open(euicc_cert_path, "wb") as f:
        f.write(euicc_cert.public_bytes(serialization.Encoding.PEM))
    
    with open(euicc_key_path, "wb") as f:
        f.write(euicc_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print(f"eUICC certificate written to: {euicc_cert_path}")
    print(f"eUICC private key written to: {euicc_key_path}")
    
    return euicc_cert, euicc_private_key

def create_ca_cert_from_ci():
    """Create a simple CA private key for testing purposes"""
    # This is a stub - in real scenarios, the CI private key would be securely managed
    # For testing, we'll create a self-signed CI certificate
    ca_private_key = generate_private_key()
    
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Virtual CI"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Virtual CI Unit"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Virtual CI Certificate"),
    ])
    
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=3650)  # 10 years
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(ca_subject)
    builder = builder.issuer_name(ca_subject)  # Self-signed
    builder = builder.public_key(ca_private_key.public_key())
    builder = builder.serial_number(int.from_bytes(os.urandom(16), byteorder="big"))
    builder = builder.not_valid_before(valid_from)
    builder = builder.not_valid_after(valid_to)
    
    # Add extensions
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
        critical=False,
    )
    
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
        critical=False,
    )
    
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=2),
        critical=True,
    )
    
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            content_commitment=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    
    # Sign the certificate
    ca_cert = builder.sign(ca_private_key, hashes.SHA256())
    
    return ca_cert, ca_private_key

def main():
    """Main function to generate all certificates"""
    # Set up paths
    script_dir = Path(__file__).parent
    certs_dir = script_dir.parent / "certs"
    certs_dir.mkdir(exist_ok=True)
    
    print("=== Virtual eUICC Certificate Generation ===")
    
    # Generate EID
    eid = generate_eid()
    print(f"Generated EID: {eid}")
    
    # For testing, create our own CI certificate
    print("\nCreating test CI certificate...")
    ci_cert, ci_private_key = create_ca_cert_from_ci()
    
    # Save CI certificate and key
    ci_cert_path = certs_dir / "ci_cert.pem"
    ci_key_path = certs_dir / "ci_key.pem"
    
    with open(ci_cert_path, "wb") as f:
        f.write(ci_cert.public_bytes(serialization.Encoding.PEM))
    
    with open(ci_key_path, "wb") as f:
        f.write(ci_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print(f"CI certificate written to: {ci_cert_path}")
    print(f"CI private key written to: {ci_key_path}")
    
    # Create EUM certificate
    print("\nCreating EUM certificate...")
    eum_cert, eum_private_key = create_eum_certificate(ci_cert, ci_private_key, eid, certs_dir)
    
    # Create eUICC certificate
    print("\nCreating eUICC certificate...")
    euicc_cert, euicc_private_key = create_euicc_certificate(eum_cert, eum_private_key, eid, certs_dir)
    
    # Save EID to configuration
    eid_file = certs_dir / "eid.txt"
    with open(eid_file, "w") as f:
        f.write(eid)
    print(f"EID written to: {eid_file}")
    
    print("\n=== Certificate Generation Complete ===")
    print(f"All certificates generated in: {certs_dir}")
    print("\nCertificate chain:")
    print("  CI (Root) -> EUM (Intermediate) -> eUICC (End Entity)")
    
    return eid

if __name__ == "__main__":
    main() 