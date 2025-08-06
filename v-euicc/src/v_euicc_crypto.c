#include "v_euicc_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// Initialize crypto context
int v_euicc_crypto_init(struct v_euicc_ecdsa_context *ctx, const char *certs_dir) {
    if (!ctx || !certs_dir) return -1;
    
    memset(ctx, 0, sizeof(struct v_euicc_ecdsa_context));
    
    // Load certificates
    char cert_path[512], key_path[512];
    
    // Load eUICC certificate
    snprintf(cert_path, sizeof(cert_path), "%s/euicc_cert.pem", certs_dir);
    snprintf(key_path, sizeof(key_path), "%s/euicc_key.pem", certs_dir);
    printf("Loading eUICC certificate from: %s\n", cert_path);
    printf("Loading eUICC private key from: %s\n", key_path);
    if (v_euicc_load_certificate(&ctx->euicc_cert, cert_path, key_path) != 0) {
        printf("Failed to load eUICC certificate\n");
        return -1;
    }
    printf("✅ eUICC certificate loaded successfully (%zu bytes)\n", ctx->euicc_cert.cert_length);
    
    // Load EUM certificate
    snprintf(cert_path, sizeof(cert_path), "%s/eum_cert.pem", certs_dir);
    snprintf(key_path, sizeof(key_path), "%s/eum_key.pem", certs_dir);
    printf("Loading EUM certificate from: %s\n", cert_path);
    printf("Loading EUM private key from: %s\n", key_path);
    if (v_euicc_load_certificate(&ctx->eum_cert, cert_path, key_path) != 0) {
        printf("Failed to load EUM certificate\n");
        return -1;
    }
    printf("✅ EUM certificate loaded successfully (%zu bytes)\n", ctx->eum_cert.cert_length);
    
    // Load CI certificate
    snprintf(cert_path, sizeof(cert_path), "%s/ci_cert.pem", certs_dir);
    snprintf(key_path, sizeof(key_path), "%s/ci_key.pem", certs_dir);
    printf("Loading CI certificate from: %s\n", cert_path);
    printf("Loading CI private key from: %s\n", key_path);
    if (v_euicc_load_certificate(&ctx->ci_cert, cert_path, key_path) != 0) {
        printf("Failed to load CI certificate\n");
        return -1;
    }
    printf("✅ CI certificate loaded successfully (%zu bytes)\n", ctx->ci_cert.cert_length);
    
    // Load EID from file
    char eid_path[512];
    snprintf(eid_path, sizeof(eid_path), "%s/eid.txt", certs_dir);
    FILE *eid_file = fopen(eid_path, "r");
    if (eid_file) {
        char eid_hex[65];
        if (fgets(eid_hex, sizeof(eid_hex), eid_file)) {
            // Convert hex string to bytes
            for (int i = 0; i < 32 && i * 2 < strlen(eid_hex); i++) {
                sscanf(eid_hex + i * 2, "%2hhx", &ctx->eid[i]);
            }
        }
        fclose(eid_file);
    }
    
    return 0;
}

void v_euicc_crypto_cleanup(struct v_euicc_ecdsa_context *ctx) {
    if (!ctx) return;
    
    v_euicc_free_certificate(&ctx->euicc_cert);
    v_euicc_free_certificate(&ctx->eum_cert);
    v_euicc_free_certificate(&ctx->ci_cert);
    
    memset(ctx, 0, sizeof(struct v_euicc_ecdsa_context));
}

int v_euicc_load_certificate(struct v_euicc_certificate *cert, const char *cert_path, const char *key_path) {
    if (!cert || !cert_path || !key_path) return -1;
    
    memset(cert, 0, sizeof(struct v_euicc_certificate));
    
    // Store paths
    cert->cert_path = strdup(cert_path);
    cert->private_key_path = strdup(key_path);
    
    // Load certificate
    FILE *cert_file = fopen(cert_path, "r");
    if (!cert_file) {
        printf("Failed to open certificate file: %s\n", cert_path);
        return -1;
    }
    
    X509 *x509_cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    
    if (!x509_cert) {
        printf("Failed to parse certificate: %s\n", cert_path);
        return -1;
    }
    
    // Convert to DER format
    cert->cert_length = i2d_X509(x509_cert, NULL);
    cert->cert_data = malloc(cert->cert_length);
    if (!cert->cert_data) {
        X509_free(x509_cert);
        return -1;
    }
    
    uint8_t *cert_ptr = cert->cert_data;
    i2d_X509(x509_cert, &cert_ptr);
    X509_free(x509_cert);
    
    // Load private key
    FILE *key_file = fopen(key_path, "r");
    if (!key_file) {
        printf("Failed to open private key file: %s\n", key_path);
        return -1;
    }
    
    EVP_PKEY *pkey = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    
    if (!pkey) {
        printf("Failed to parse private key: %s\n", key_path);
        return -1;
    }
    
    // Convert to DER format
    cert->private_key_length = i2d_PrivateKey(pkey, NULL);
    cert->private_key_data = malloc(cert->private_key_length);
    if (!cert->private_key_data) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    uint8_t *key_ptr = cert->private_key_data;
    i2d_PrivateKey(pkey, &key_ptr);
    EVP_PKEY_free(pkey);
    
    return 0;
}

void v_euicc_free_certificate(struct v_euicc_certificate *cert) {
    if (!cert) return;
    
    free(cert->cert_data);
    free(cert->private_key_data);
    free(cert->cert_path);
    free(cert->private_key_path);
    
    memset(cert, 0, sizeof(struct v_euicc_certificate));
}

int v_euicc_ecdsa_sign(const struct v_euicc_certificate *cert, 
                       const uint8_t *data, size_t data_len,
                       uint8_t *signature, size_t *signature_len) {
    if (!cert || !data || !signature || !signature_len) return -1;
    
    // Load private key from DER data
    const uint8_t *key_ptr = cert->private_key_data;
    EVP_PKEY *pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &key_ptr, cert->private_key_length);
    if (!pkey) {
        printf("Failed to load private key for signing\n");
        return -1;
    }
    
    // Create signing context
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    // Initialize signing
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        printf("Failed to initialize ECDSA signing\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    // Update with data
    if (EVP_DigestSignUpdate(mdctx, data, data_len) <= 0) {
        printf("Failed to update ECDSA signing\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    // Finalize signature
    if (EVP_DigestSignFinal(mdctx, signature, signature_len) <= 0) {
        printf("Failed to finalize ECDSA signature\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return 0;
}

int v_euicc_ecdsa_verify(const struct v_euicc_certificate *cert,
                         const uint8_t *data, size_t data_len,
                         const uint8_t *signature, size_t signature_len) {
    if (!cert || !data || !signature) return -1;
    
    // Load certificate from DER data
    const uint8_t *cert_ptr = cert->cert_data;
    X509 *x509_cert = d2i_X509(NULL, &cert_ptr, cert->cert_length);
    if (!x509_cert) {
        printf("Failed to load certificate for verification\n");
        return -1;
    }
    
    // Extract public key
    EVP_PKEY *pkey = X509_get_pubkey(x509_cert);
    X509_free(x509_cert);
    if (!pkey) {
        printf("Failed to extract public key from certificate\n");
        return -1;
    }
    
    // Create verification context
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    // Initialize verification
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        printf("Failed to initialize ECDSA verification\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    // Update with data
    if (EVP_DigestVerifyUpdate(mdctx, data, data_len) <= 0) {
        printf("Failed to update ECDSA verification\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    // Verify signature
    int result = EVP_DigestVerifyFinal(mdctx, signature, signature_len);
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    
    return (result == 1) ? 0 : -1;
}

int v_euicc_generate_challenge(uint8_t *challenge) {
    if (!challenge) return -1;
    
    if (RAND_bytes(challenge, V_EUICC_CHALLENGE_LENGTH) != 1) {
        printf("Failed to generate random challenge\n");
        return -1;
    }
    
    return 0;
}

// Simple ASN.1 helpers for SGP.22 structures
int v_euicc_create_euicc_info1(const struct v_euicc_ecdsa_context *ctx,
                               uint8_t **euicc_info1, size_t *euicc_info1_len) {
    if (!ctx || !euicc_info1 || !euicc_info1_len) return -1;
    
    // Create a simple EUICCInfo1 structure
    // BF20 [length] 82 03 [SGP.22 version] 89 14 [CI PKID] 8A 14 [CI PKID]
    
    uint8_t *buffer = malloc(256);
    if (!buffer) return -1;
    
    int pos = 0;
    
    // BF20 tag (EUICCInfo1)
    buffer[pos++] = 0xBF;
    buffer[pos++] = 0x20;
    buffer[pos++] = 0x28; // Length (will be updated)
    
    // SVN [2] VersionType (SGP.22 v2.2.1)
    buffer[pos++] = 0x82; // tag [2]
    buffer[pos++] = 0x03; // length
    buffer[pos++] = 0x02; // major version 2
    buffer[pos++] = 0x02; // minor version 2
    buffer[pos++] = 0x01; // revision 1
    
    // euiccCiPKIdListForVerification [9]
    buffer[pos++] = 0x89; // tag [9]
    buffer[pos++] = 0x14; // length (20 bytes)
    // Use first 20 bytes of CI certificate data as key identifier
    memcpy(buffer + pos, ctx->ci_cert.cert_data, 20);
    pos += 20;
    
    // euiccCiPKIdListForSigning [10]
    buffer[pos++] = 0x8A; // tag [10]
    buffer[pos++] = 0x14; // length (20 bytes)
    // Same CI key identifier
    memcpy(buffer + pos, ctx->ci_cert.cert_data, 20);
    pos += 20;
    
    // Update length field
    buffer[2] = pos - 3;
    
    *euicc_info1 = buffer;
    *euicc_info1_len = pos;
    
    return 0;
}

int v_euicc_create_authenticate_server_response(const struct v_euicc_ecdsa_context *ctx,
                                                const uint8_t *server_address, size_t server_address_len,
                                                uint8_t **response, size_t *response_len) {
    if (!ctx || !response || !response_len) return -1;
    
    // Create euiccSigned1 structure
    // SEQUENCE {
    //   transactionId [0] TransactionId,
    //   serverAddress [3] UTF8String,
    //   serverChallenge [4] Octet16,
    //   euiccInfo2 [34] EUICCInfo2,
    //   ctxParams1 CtxParams1
    // }
    
    uint8_t *euicc_signed1 = malloc(2048);
    if (!euicc_signed1) return -1;
    
    int pos = 0;
    
    // SEQUENCE tag
    euicc_signed1[pos++] = 0x30;
    int length_pos = pos++;
    
    // transactionId [0]
    euicc_signed1[pos++] = 0x80; // [0] IMPLICIT
    euicc_signed1[pos++] = ctx->transaction_id_length;
    memcpy(euicc_signed1 + pos, ctx->transaction_id, ctx->transaction_id_length);
    pos += ctx->transaction_id_length;
    
    // serverAddress [3]
    if (server_address && server_address_len > 0) {
        euicc_signed1[pos++] = 0x83; // [3] IMPLICIT UTF8String
        euicc_signed1[pos++] = server_address_len;
        memcpy(euicc_signed1 + pos, server_address, server_address_len);
        pos += server_address_len;
    }
    
    // serverChallenge [4]
    euicc_signed1[pos++] = 0x84; // [4] IMPLICIT OCTET STRING
    euicc_signed1[pos++] = V_EUICC_CHALLENGE_LENGTH;
    memcpy(euicc_signed1 + pos, ctx->server_challenge, V_EUICC_CHALLENGE_LENGTH);
    pos += V_EUICC_CHALLENGE_LENGTH;
    
    // euiccInfo2 [34] - simplified version
    euicc_signed1[pos++] = 0xBF;
    euicc_signed1[pos++] = 0x22; // tag [34]
    euicc_signed1[pos++] = 0x05; // length
    euicc_signed1[pos++] = 0x82; // SVN tag
    euicc_signed1[pos++] = 0x03; // length
    euicc_signed1[pos++] = 0x02; // major
    euicc_signed1[pos++] = 0x02; // minor
    euicc_signed1[pos++] = 0x01; // revision
    
    // ctxParams1 - simplified
    euicc_signed1[pos++] = 0x30; // SEQUENCE
    euicc_signed1[pos++] = 0x02; // length
    euicc_signed1[pos++] = 0x01; // INTEGER
    euicc_signed1[pos++] = 0x00; // value
    
    // Update SEQUENCE length
    euicc_signed1[length_pos] = pos - length_pos - 1;
    
    // Sign euiccSigned1
    uint8_t signature[V_EUICC_MAX_SIGNATURE_SIZE];
    size_t signature_len = V_EUICC_MAX_SIGNATURE_SIZE;
    
    if (v_euicc_ecdsa_sign(&ctx->euicc_cert, euicc_signed1, pos, signature, &signature_len) != 0) {
        free(euicc_signed1);
        return -1;
    }
    
    // Create complete AuthenticateServerResponse
    uint8_t *auth_response = malloc(4096);
    if (!auth_response) {
        free(euicc_signed1);
        return -1;
    }
    
    int resp_pos = 0;
    
    // BF38 tag (AuthenticateServerResponse)
    auth_response[resp_pos++] = 0xBF;
    auth_response[resp_pos++] = 0x38;
    int resp_length_pos = resp_pos++;
    
    // authenticateResponseOk SEQUENCE
    auth_response[resp_pos++] = 0x30;
    int ok_length_pos = resp_pos++;
    
    // euiccSigned1
    memcpy(auth_response + resp_pos, euicc_signed1, pos);
    resp_pos += pos;
    
    // euiccSignature1 [APPLICATION 55]
    auth_response[resp_pos++] = 0x5F;
    auth_response[resp_pos++] = 0x37;
    auth_response[resp_pos++] = signature_len;
    memcpy(auth_response + resp_pos, signature, signature_len);
    resp_pos += signature_len;
    
    // euiccCertificate
    auth_response[resp_pos++] = 0x30; // SEQUENCE (simplified certificate)
    auth_response[resp_pos++] = ctx->euicc_cert.cert_length;
    memcpy(auth_response + resp_pos, ctx->euicc_cert.cert_data, ctx->euicc_cert.cert_length);
    resp_pos += ctx->euicc_cert.cert_length;
    
    // eumCertificate
    auth_response[resp_pos++] = 0x30; // SEQUENCE (simplified certificate)
    auth_response[resp_pos++] = ctx->eum_cert.cert_length;
    memcpy(auth_response + resp_pos, ctx->eum_cert.cert_data, ctx->eum_cert.cert_length);
    resp_pos += ctx->eum_cert.cert_length;
    
    // Update lengths
    auth_response[ok_length_pos] = resp_pos - ok_length_pos - 1;
    auth_response[resp_length_pos] = resp_pos - resp_length_pos - 1;
    
    free(euicc_signed1);
    
    *response = auth_response;
    *response_len = resp_pos;
    
    return 0;
}

// Basic ASN.1 parsing for AuthenticateServer request
int v_euicc_parse_authenticate_server_request(const uint8_t *apdu_data, size_t data_len,
                                              uint8_t **server_signed1, size_t *server_signed1_len,
                                              uint8_t **server_signature1, size_t *server_signature1_len,
                                              uint8_t **euicc_ci_pkid, size_t *euicc_ci_pkid_len,
                                              uint8_t **server_certificate, size_t *server_certificate_len) {
    // Simplified ASN.1 parsing - in a real implementation, use a proper ASN.1 library
    // For now, we'll extract the basic structure
    
    if (!apdu_data || data_len < 10) return -1;
    
    // Look for BF38 tag (AuthenticateServerRequest)
    for (size_t i = 0; i < data_len - 2; i++) {
        if (apdu_data[i] == 0xBF && apdu_data[i + 1] == 0x38) {
            // Found the tag, parse the content
            size_t content_len = apdu_data[i + 2];
            const uint8_t *content = apdu_data + i + 3;
            
            // For now, return dummy data indicating we found the structure
            if (server_signed1 && server_signed1_len) {
                *server_signed1_len = 32; // dummy
                *server_signed1 = malloc(32);
                memset(*server_signed1, 0xAA, 32);
            }
            
            if (server_signature1 && server_signature1_len) {
                *server_signature1_len = 64; // dummy
                *server_signature1 = malloc(64);
                memset(*server_signature1, 0xBB, 64);
            }
            
            return 0;
        }
    }
    
    return -1;
} 