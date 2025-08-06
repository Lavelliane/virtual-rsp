#!/usr/bin/env python3
"""
Setup TLS certificates for SGP.22 authentication with ECDSA support.
Creates proper certificate chain for SM-DP+ server TLS communication.
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

def generate_ecdsa_private_key():
    """Generate ECDSA private key using P-256 curve"""
    return ec.generate_private_key(ec.SECP256R1())

def create_ca_certificate(output_dir):
    """Create a CA certificate for TLS"""
    ca_private_key = generate_ecdsa_private_key()
    
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Virtual eSIM Test CA"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Test CA Unit"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Virtual eSIM Test CA"),
    ])
    
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=3650)  # 10 years
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(ca_subject)
    builder = builder.issuer_name(ca_subject)  # Self-signed
    builder = builder.public_key(ca_private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
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
        x509.BasicConstraints(ca=True, path_length=None),
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
    
    # Save CA certificate and private key
    ca_cert_path = output_dir / "tls_ca_cert.pem"
    ca_key_path = output_dir / "tls_ca_key.pem"
    
    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    
    with open(ca_key_path, "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print(f"CA certificate written to: {ca_cert_path}")
    print(f"CA private key written to: {ca_key_path}")
    
    return ca_cert, ca_private_key

def create_sm_dp_server_certificate(ca_cert, ca_private_key, hostname, output_dir):
    """Create SM-DP+ server certificate for TLS"""
    server_private_key = generate_ecdsa_private_key()
    
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Virtual SM-DP+ Server"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "SM-DP+ Unit"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=365)  # 1 year
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(server_subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(server_private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(valid_from)
    builder = builder.not_valid_after(valid_to)
    
    # Add extensions
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(server_private_key.public_key()),
        critical=False,
    )
    
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False,
    )
    
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            data_encipherment=False,
            content_commitment=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    
    # Add Extended Key Usage for TLS server
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
        ]),
        critical=True,
    )
    
    # Add Subject Alternative Name
    san_list = [x509.DNSName(hostname)]
    if hostname == "localhost" or hostname == "127.0.0.1":
        san_list.extend([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.IPAddress(ipaddress.ip_address("::1")),
        ])
    
    builder = builder.add_extension(
        x509.SubjectAlternativeName(san_list),
        critical=False,
    )
    
    # Sign the certificate
    server_cert = builder.sign(ca_private_key, hashes.SHA256())
    
    # Save server certificate and private key
    server_cert_path = output_dir / "tls_server_cert.pem"
    server_key_path = output_dir / "tls_server_key.pem"
    
    with open(server_cert_path, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))
    
    with open(server_key_path, "wb") as f:
        f.write(server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print(f"Server certificate written to: {server_cert_path}")
    print(f"Server private key written to: {server_key_path}")
    
    return server_cert, server_private_key

def create_client_certificate(ca_cert, ca_private_key, output_dir):
    """Create client certificate for mutual TLS authentication"""
    client_private_key = generate_ecdsa_private_key()
    
    client_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Virtual LPA Client"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "LPA Unit"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Virtual LPA Client"),
    ])
    
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=365)  # 1 year
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(client_subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(client_private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(valid_from)
    builder = builder.not_valid_after(valid_to)
    
    # Add extensions
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(client_private_key.public_key()),
        critical=False,
    )
    
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False,
    )
    
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            data_encipherment=False,
            content_commitment=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    
    # Add Extended Key Usage for TLS client
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=True,
    )
    
    # Sign the certificate
    client_cert = builder.sign(ca_private_key, hashes.SHA256())
    
    # Save client certificate and private key
    client_cert_path = output_dir / "tls_client_cert.pem"
    client_key_path = output_dir / "tls_client_key.pem"
    
    with open(client_cert_path, "wb") as f:
        f.write(client_cert.public_bytes(serialization.Encoding.PEM))
    
    with open(client_key_path, "wb") as f:
        f.write(client_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print(f"Client certificate written to: {client_cert_path}")
    print(f"Client private key written to: {client_key_path}")
    
    return client_cert, client_private_key

def main():
    """Main function to generate TLS certificates"""
    script_dir = Path(__file__).parent
    certs_dir = script_dir.parent / "certs"
    certs_dir.mkdir(exist_ok=True)
    
    print("=== TLS Certificate Generation for SGP.22 Authentication ===")
    
    hostname = "testsmdpplus1.example.com"
    
    # Create CA certificate
    print("\nCreating CA certificate...")
    ca_cert, ca_private_key = create_ca_certificate(certs_dir)
    
    # Create SM-DP+ server certificate
    print(f"\nCreating SM-DP+ server certificate for {hostname}...")
    server_cert, server_private_key = create_sm_dp_server_certificate(
        ca_cert, ca_private_key, hostname, certs_dir)
    
    # Create client certificate for mutual TLS
    print("\nCreating client certificate...")
    client_cert, client_private_key = create_client_certificate(
        ca_cert, ca_private_key, certs_dir)
    
    print("\n=== TLS Certificate Generation Complete ===")
    print(f"All TLS certificates generated in: {certs_dir}")
    print("\nCertificate chain:")
    print("  TLS CA (Root) -> SM-DP+ Server (TLS)")
    print("  TLS CA (Root) -> LPA Client (TLS)")
    print("\nFor SGP.22 authentication:")
    print("  CI (Root) -> EUM (Intermediate) -> eUICC (End Entity)")
    
    return True

if __name__ == "__main__":
    main() 