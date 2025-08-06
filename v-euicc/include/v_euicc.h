#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#define V_EUICC_VERSION_MAJOR 1
#define V_EUICC_VERSION_MINOR 0
#define V_EUICC_VERSION_PATCH 0

#define V_EUICC_MAX_PROFILES 8
#define V_EUICC_EID_LENGTH 32
#define V_EUICC_ICCID_LENGTH 10
#define V_EUICC_AID_MAX_LENGTH 16
#define V_EUICC_PROFILE_NAME_MAX_LENGTH 64
#define V_EUICC_SPN_MAX_LENGTH 32

// Virtual eUICC communication methods
enum v_euicc_comm_method {
    V_EUICC_COMM_UNIX_SOCKET,
    V_EUICC_COMM_TCP_SOCKET,
    V_EUICC_COMM_SHARED_MEMORY
};

// Certificate types for flexible certificate handling
enum v_euicc_cert_type {
    V_EUICC_CERT_ECDSA_P256,
    V_EUICC_CERT_ECDSA_P384,
    V_EUICC_CERT_RSA_2048,
    V_EUICC_CERT_RSA_4096,
    V_EUICC_CERT_PQC_DILITHIUM2,  // Future PQC support
    V_EUICC_CERT_PQC_DILITHIUM3,
    V_EUICC_CERT_PQC_DILITHIUM5,
    V_EUICC_CERT_PQC_FALCON512,
    V_EUICC_CERT_PQC_FALCON1024
};

// Virtual profile states
enum v_euicc_profile_state {
    V_EUICC_PROFILE_STATE_DISABLED = 0,
    V_EUICC_PROFILE_STATE_ENABLED = 1
};

// Virtual profile classes
enum v_euicc_profile_class {
    V_EUICC_PROFILE_CLASS_TEST = 0,
    V_EUICC_PROFILE_CLASS_PROVISIONING = 1,
    V_EUICC_PROFILE_CLASS_OPERATIONAL = 2
};

// Virtual profile structure
struct v_euicc_profile {
    uint8_t iccid[V_EUICC_ICCID_LENGTH];
    uint8_t aid[V_EUICC_AID_MAX_LENGTH];
    uint8_t aid_len;
    enum v_euicc_profile_state state;
    enum v_euicc_profile_class class;
    char nickname[V_EUICC_PROFILE_NAME_MAX_LENGTH];
    char service_provider_name[V_EUICC_SPN_MAX_LENGTH];
    char profile_name[V_EUICC_PROFILE_NAME_MAX_LENGTH];
    uint8_t *profile_data;
    size_t profile_data_len;
    bool allocated;
};

// Certificate configuration structure
struct v_euicc_cert_config {
    enum v_euicc_cert_type type;
    char *cert_path;
    char *private_key_path;
    char *ca_cert_path;
    bool pqc_enabled;
    // Future: PQC-specific parameters
    void *pqc_params;
};

// Virtual eUICC configuration
struct v_euicc_config {
    char eid[V_EUICC_EID_LENGTH + 1];
    char default_smdp_address[256];
    char root_smds_address[256];
    enum v_euicc_comm_method comm_method;
    char comm_address[256];
    int comm_port;
    struct v_euicc_cert_config euicc_cert;
    struct v_euicc_cert_config eum_cert;
    bool debug_mode;
    char storage_path[256];
};

// Virtual eUICC context
struct v_euicc_ctx {
    struct v_euicc_config config;
    struct v_euicc_profile profiles[V_EUICC_MAX_PROFILES];
    int num_profiles;
    int enabled_profile_index;
    
    // Communication
    int comm_fd;
    pthread_t comm_thread;
    bool running;
    pthread_mutex_t mutex;
    
    // Session state
    uint8_t *current_transaction_id;
    size_t transaction_id_len;
    uint8_t euicc_challenge[16];
    
    // Certificate handling
    void *cert_ctx;  // Flexible certificate context
    
    // Storage
    char storage_file[512];
};

// Function declarations

// Core virtual eUICC functions
int v_euicc_init(struct v_euicc_ctx *ctx, const char *config_file);
void v_euicc_fini(struct v_euicc_ctx *ctx);
int v_euicc_start(struct v_euicc_ctx *ctx);
void v_euicc_stop(struct v_euicc_ctx *ctx);

// Configuration management
int v_euicc_load_config(struct v_euicc_config *config, const char *config_file);
int v_euicc_save_config(const struct v_euicc_config *config, const char *config_file);

// Profile management
int v_euicc_add_profile(struct v_euicc_ctx *ctx, const struct v_euicc_profile *profile);
int v_euicc_remove_profile(struct v_euicc_ctx *ctx, const uint8_t *iccid);
int v_euicc_enable_profile(struct v_euicc_ctx *ctx, const uint8_t *iccid);
int v_euicc_disable_profile(struct v_euicc_ctx *ctx, const uint8_t *iccid);
struct v_euicc_profile *v_euicc_find_profile(struct v_euicc_ctx *ctx, const uint8_t *iccid);

// Storage management
int v_euicc_load_storage(struct v_euicc_ctx *ctx);
int v_euicc_save_storage(struct v_euicc_ctx *ctx);

// Certificate management (flexible for PQC)
int v_euicc_cert_init(struct v_euicc_ctx *ctx);
void v_euicc_cert_fini(struct v_euicc_ctx *ctx);
int v_euicc_cert_sign(struct v_euicc_ctx *ctx, const uint8_t *data, size_t data_len, 
                      uint8_t **signature, size_t *sig_len);
int v_euicc_cert_verify(struct v_euicc_ctx *ctx, const uint8_t *data, size_t data_len,
                        const uint8_t *signature, size_t sig_len);

// Communication layer
int v_euicc_comm_init(struct v_euicc_ctx *ctx);
void v_euicc_comm_fini(struct v_euicc_ctx *ctx);
void *v_euicc_comm_thread(void *arg);

// SGP.22 ES10a operations
int v_euicc_es10a_get_configured_addresses(struct v_euicc_ctx *ctx, 
                                           char **default_smdp, char **root_smds);
int v_euicc_es10a_set_default_smdp(struct v_euicc_ctx *ctx, const char *smdp_address);

// SGP.22 ES10b operations  
int v_euicc_es10b_get_euicc_challenge(struct v_euicc_ctx *ctx, uint8_t *challenge);
int v_euicc_es10b_get_euicc_info1(struct v_euicc_ctx *ctx, uint8_t **info, size_t *info_len);
int v_euicc_es10b_get_euicc_info2(struct v_euicc_ctx *ctx, uint8_t **info, size_t *info_len);
int v_euicc_es10b_authenticate_server(struct v_euicc_ctx *ctx, 
                                      const uint8_t *server_signed1, size_t server_signed1_len,
                                      const uint8_t *server_signature1, size_t server_sig1_len,
                                      const uint8_t *server_cert, size_t server_cert_len,
                                      uint8_t **auth_response, size_t *auth_response_len);
int v_euicc_es10b_prepare_download(struct v_euicc_ctx *ctx,
                                   const uint8_t *prepare_download_req, size_t req_len,
                                   uint8_t **prepare_download_resp, size_t *resp_len);
int v_euicc_es10b_load_bound_profile_package(struct v_euicc_ctx *ctx,
                                             const uint8_t *bpp, size_t bpp_len,
                                             uint8_t **result, size_t *result_len);

// SGP.22 ES10c operations
int v_euicc_es10c_get_profiles_info(struct v_euicc_ctx *ctx, 
                                    uint8_t **profiles_info, size_t *info_len);
int v_euicc_es10c_enable_profile(struct v_euicc_ctx *ctx, const uint8_t *iccid, bool refresh);
int v_euicc_es10c_disable_profile(struct v_euicc_ctx *ctx, const uint8_t *iccid, bool refresh);
int v_euicc_es10c_delete_profile(struct v_euicc_ctx *ctx, const uint8_t *iccid);

// Utility functions
void v_euicc_generate_eid(char *eid);
void v_euicc_generate_iccid(uint8_t *iccid);
int v_euicc_hex_to_bin(const char *hex, uint8_t *bin, size_t max_len);
int v_euicc_bin_to_hex(const uint8_t *bin, size_t bin_len, char *hex, size_t hex_size);

// Error codes
#define V_EUICC_SUCCESS                    0
#define V_EUICC_ERROR_INVALID_PARAMETER   -1
#define V_EUICC_ERROR_MEMORY_ALLOCATION   -2
#define V_EUICC_ERROR_FILE_IO             -3
#define V_EUICC_ERROR_COMMUNICATION       -4
#define V_EUICC_ERROR_CERTIFICATE         -5
#define V_EUICC_ERROR_PROFILE_NOT_FOUND   -6
#define V_EUICC_ERROR_PROFILE_ALREADY_EXISTS -7
#define V_EUICC_ERROR_INVALID_STATE       -8
#define V_EUICC_ERROR_NOT_IMPLEMENTED     -9
#define V_EUICC_ERROR_UNKNOWN             -10 