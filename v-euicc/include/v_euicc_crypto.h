#pragma once

#include <stdint.h>
#include <stddef.h>

#define V_EUICC_EID_LENGTH 32
#define V_EUICC_CHALLENGE_LENGTH 16
#define V_EUICC_MAX_CERT_SIZE 2048
#define V_EUICC_MAX_SIGNATURE_SIZE 256

// Certificate structure
struct v_euicc_certificate {
    uint8_t *cert_data;
    size_t cert_length;
    uint8_t *private_key_data;
    size_t private_key_length;
    char *cert_path;
    char *private_key_path;
};

// ECDSA signature context
struct v_euicc_ecdsa_context {
    struct v_euicc_certificate euicc_cert;
    struct v_euicc_certificate eum_cert;
    struct v_euicc_certificate ci_cert;
    uint8_t eid[V_EUICC_EID_LENGTH];
    uint8_t current_challenge[V_EUICC_CHALLENGE_LENGTH];
    uint8_t server_challenge[V_EUICC_CHALLENGE_LENGTH];
    uint8_t transaction_id[16];
    size_t transaction_id_length;
};

// Function declarations
int v_euicc_crypto_init(struct v_euicc_ecdsa_context *ctx, const char *certs_dir);
void v_euicc_crypto_cleanup(struct v_euicc_ecdsa_context *ctx);

int v_euicc_load_certificate(struct v_euicc_certificate *cert, const char *cert_path, const char *key_path);
void v_euicc_free_certificate(struct v_euicc_certificate *cert);

int v_euicc_ecdsa_sign(const struct v_euicc_certificate *cert, 
                       const uint8_t *data, size_t data_len,
                       uint8_t *signature, size_t *signature_len);

int v_euicc_ecdsa_verify(const struct v_euicc_certificate *cert,
                         const uint8_t *data, size_t data_len,
                         const uint8_t *signature, size_t signature_len);

// ECDSA helpers for GSMA/GP TR-03111 raw r||s signatures
// Sign and return 64-byte TR-03111 (r||s) signature
int v_euicc_ecdsa_sign_tr03111(const struct v_euicc_certificate *cert,
                               const uint8_t *data, size_t data_len,
                               uint8_t *signature_out, size_t *signature_out_len);

// Convert 64-byte TR-03111 (r||s) signature to DER-encoded ECDSA signature
int v_euicc_tr03111_to_der(const uint8_t *tr_sig, size_t tr_sig_len,
                           uint8_t **der_sig, size_t *der_sig_len);

int v_euicc_generate_challenge(uint8_t *challenge);

// ASN.1 helper functions
int v_euicc_parse_authenticate_server_request(const uint8_t *apdu_data, size_t data_len,
                                              uint8_t **server_signed1, size_t *server_signed1_len,
                                              uint8_t **server_signature1, size_t *server_signature1_len,
                                              uint8_t **euicc_ci_pkid, size_t *euicc_ci_pkid_len,
                                              uint8_t **server_certificate, size_t *server_certificate_len);

int v_euicc_create_authenticate_server_response(const struct v_euicc_ecdsa_context *ctx,
                                                const uint8_t *server_address, size_t server_address_len,
                                                uint8_t **response, size_t *response_len);

int v_euicc_create_euicc_info1(const struct v_euicc_ecdsa_context *ctx,
                               uint8_t **euicc_info1, size_t *euicc_info1_len);

int v_euicc_create_euicc_info2(const struct v_euicc_ecdsa_context *ctx,
                               uint8_t **euicc_info2, size_t *euicc_info2_len); 