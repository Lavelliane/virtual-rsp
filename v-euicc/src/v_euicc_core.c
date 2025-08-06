#include "../include/v_euicc.h"
#include "../include/v_euicc_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

// Static variables for virtual eUICC instance
static struct v_euicc_ctx *g_v_euicc_ctx = NULL;

// Utility function implementations
void v_euicc_generate_eid(char *eid) {
    static const char chars[] = "0123456789ABCDEF";
    srand(time(NULL));
    
    // Generate a 32-character hex EID
    for (int i = 0; i < V_EUICC_EID_LENGTH; i++) {
        eid[i] = chars[rand() % 16];
    }
    eid[V_EUICC_EID_LENGTH] = '\0';
}

void v_euicc_generate_iccid(uint8_t *iccid) {
    srand(time(NULL));
    for (int i = 0; i < V_EUICC_ICCID_LENGTH; i++) {
        iccid[i] = rand() % 256;
    }
}

int v_euicc_hex_to_bin(const char *hex, uint8_t *bin, size_t max_len) {
    if (!hex || !bin) return V_EUICC_ERROR_INVALID_PARAMETER;
    
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_len) {
        return V_EUICC_ERROR_INVALID_PARAMETER;
    }
    
    for (size_t i = 0; i < hex_len; i += 2) {
        unsigned int byte;
        if (sscanf(&hex[i], "%2x", &byte) != 1) {
            return V_EUICC_ERROR_INVALID_PARAMETER;
        }
        bin[i / 2] = (uint8_t)byte;
    }
    
    return hex_len / 2;
}

int v_euicc_bin_to_hex(const uint8_t *bin, size_t bin_len, char *hex, size_t hex_size) {
    if (!bin || !hex || hex_size < (bin_len * 2 + 1)) {
        return V_EUICC_ERROR_INVALID_PARAMETER;
    }
    
    for (size_t i = 0; i < bin_len; i++) {
        sprintf(&hex[i * 2], "%02X", bin[i]);
    }
    hex[bin_len * 2] = '\0';
    
    return V_EUICC_SUCCESS;
}

// Configuration management
int v_euicc_load_config(struct v_euicc_config *config, const char *config_file) {
    if (!config) return V_EUICC_ERROR_INVALID_PARAMETER;
    
    // Set default values
    memset(config, 0, sizeof(struct v_euicc_config));
    
    // Use the generated EID from certificate generation
    strcpy(config->eid, "EE2EC83C448C489BCD3019AD1F811755");
    
    strcpy(config->default_smdp_address, "testsmdpplus1.example.com");
    strcpy(config->root_smds_address, "prod.smds.gsma.com");
    config->comm_method = V_EUICC_COMM_UNIX_SOCKET;
    strcpy(config->comm_address, "/tmp/v-euicc.sock");
    config->comm_port = 8765;
    config->debug_mode = true;
    strcpy(config->storage_path, "./storage");
    
    // Certificate configuration with generated ECDSA certificates
    config->euicc_cert.type = V_EUICC_CERT_ECDSA_P256;
    config->euicc_cert.cert_path = strdup("./certs/euicc_cert.pem");
    config->euicc_cert.private_key_path = strdup("./certs/euicc_key.pem");
    config->euicc_cert.ca_cert_path = strdup("./certs/ci_cert.pem");
    config->euicc_cert.pqc_enabled = false;
    
    config->eum_cert.type = V_EUICC_CERT_ECDSA_P256;
    config->eum_cert.cert_path = strdup("./certs/eum_cert.pem");
    config->eum_cert.private_key_path = strdup("./certs/eum_key.pem");
    config->eum_cert.ca_cert_path = strdup("./certs/ci_cert.pem");
    config->eum_cert.pqc_enabled = false;
    
    // If config file is provided, try to parse it
    if (config_file) {
        // TODO: Parse actual config file (JSON/INI format)
        // For now, use defaults even if config_file is provided
    }
    
    return V_EUICC_SUCCESS;
}

int v_euicc_save_config(const struct v_euicc_config *config, const char *config_file) {
    if (!config || !config_file) return V_EUICC_ERROR_INVALID_PARAMETER;
    
    FILE *fp = fopen(config_file, "w");
    if (!fp) return V_EUICC_ERROR_FILE_IO;
    
    // Write configuration in JSON format
    fprintf(fp, "{\n");
    fprintf(fp, "  \"eid\": \"%s\",\n", config->eid);
    fprintf(fp, "  \"default_smdp_address\": \"%s\",\n", config->default_smdp_address);
    fprintf(fp, "  \"root_smds_address\": \"%s\",\n", config->root_smds_address);
    fprintf(fp, "  \"comm_method\": %d,\n", config->comm_method);
    fprintf(fp, "  \"comm_address\": \"%s\",\n", config->comm_address);
    fprintf(fp, "  \"comm_port\": %d,\n", config->comm_port);
    fprintf(fp, "  \"debug_mode\": %s,\n", config->debug_mode ? "true" : "false");
    fprintf(fp, "  \"storage_path\": \"%s\"\n", config->storage_path);
    fprintf(fp, "}\n");
    
    fclose(fp);
    return V_EUICC_SUCCESS;
}

// Profile management
struct v_euicc_profile *v_euicc_find_profile(struct v_euicc_ctx *ctx, const uint8_t *iccid) {
    if (!ctx || !iccid) return NULL;
    
    for (int i = 0; i < ctx->num_profiles; i++) {
        if (memcmp(ctx->profiles[i].iccid, iccid, V_EUICC_ICCID_LENGTH) == 0) {
            return &ctx->profiles[i];
        }
    }
    return NULL;
}

int v_euicc_add_profile(struct v_euicc_ctx *ctx, const struct v_euicc_profile *profile) {
    if (!ctx || !profile) return V_EUICC_ERROR_INVALID_PARAMETER;
    
    if (ctx->num_profiles >= V_EUICC_MAX_PROFILES) {
        return V_EUICC_ERROR_INVALID_STATE;
    }
    
    // Check if profile already exists
    if (v_euicc_find_profile(ctx, profile->iccid)) {
        return V_EUICC_ERROR_PROFILE_ALREADY_EXISTS;
    }
    
    // Add profile
    ctx->profiles[ctx->num_profiles] = *profile;
    ctx->num_profiles++;
    
    return V_EUICC_SUCCESS;
}

int v_euicc_remove_profile(struct v_euicc_ctx *ctx, const uint8_t *iccid) {
    if (!ctx || !iccid) return V_EUICC_ERROR_INVALID_PARAMETER;
    
    for (int i = 0; i < ctx->num_profiles; i++) {
        if (memcmp(ctx->profiles[i].iccid, iccid, V_EUICC_ICCID_LENGTH) == 0) {
            // Free profile data if allocated
            if (ctx->profiles[i].allocated && ctx->profiles[i].profile_data) {
                free(ctx->profiles[i].profile_data);
            }
            
            // Move remaining profiles
            for (int j = i; j < ctx->num_profiles - 1; j++) {
                ctx->profiles[j] = ctx->profiles[j + 1];
            }
            ctx->num_profiles--;
            
            // Update enabled profile index if necessary
            if (ctx->enabled_profile_index == i) {
                ctx->enabled_profile_index = -1;
            } else if (ctx->enabled_profile_index > i) {
                ctx->enabled_profile_index--;
            }
            
            return V_EUICC_SUCCESS;
        }
    }
    
    return V_EUICC_ERROR_PROFILE_NOT_FOUND;
}

int v_euicc_enable_profile(struct v_euicc_ctx *ctx, const uint8_t *iccid) {
    if (!ctx || !iccid) return V_EUICC_ERROR_INVALID_PARAMETER;
    
    // Disable currently enabled profile
    if (ctx->enabled_profile_index >= 0) {
        ctx->profiles[ctx->enabled_profile_index].state = V_EUICC_PROFILE_STATE_DISABLED;
    }
    
    // Find and enable new profile
    for (int i = 0; i < ctx->num_profiles; i++) {
        if (memcmp(ctx->profiles[i].iccid, iccid, V_EUICC_ICCID_LENGTH) == 0) {
            ctx->profiles[i].state = V_EUICC_PROFILE_STATE_ENABLED;
            ctx->enabled_profile_index = i;
            return V_EUICC_SUCCESS;
        }
    }
    
    return V_EUICC_ERROR_PROFILE_NOT_FOUND;
}

int v_euicc_disable_profile(struct v_euicc_ctx *ctx, const uint8_t *iccid) {
    if (!ctx || !iccid) return V_EUICC_ERROR_INVALID_PARAMETER;
    
    for (int i = 0; i < ctx->num_profiles; i++) {
        if (memcmp(ctx->profiles[i].iccid, iccid, V_EUICC_ICCID_LENGTH) == 0) {
            ctx->profiles[i].state = V_EUICC_PROFILE_STATE_DISABLED;
            if (ctx->enabled_profile_index == i) {
                ctx->enabled_profile_index = -1;
            }
            return V_EUICC_SUCCESS;
        }
    }
    
    return V_EUICC_ERROR_PROFILE_NOT_FOUND;
}

// Storage management
int v_euicc_load_storage(struct v_euicc_ctx *ctx) {
    if (!ctx) return V_EUICC_ERROR_INVALID_PARAMETER;
    
    FILE *fp = fopen(ctx->storage_file, "rb");
    if (!fp) {
        // Storage file doesn't exist, start with empty profiles
        ctx->num_profiles = 0;
        ctx->enabled_profile_index = -1;
        return V_EUICC_SUCCESS;
    }
    
    // Read number of profiles
    if (fread(&ctx->num_profiles, sizeof(int), 1, fp) != 1) {
        fclose(fp);
        return V_EUICC_ERROR_FILE_IO;
    }
    
    // Read enabled profile index
    if (fread(&ctx->enabled_profile_index, sizeof(int), 1, fp) != 1) {
        fclose(fp);
        return V_EUICC_ERROR_FILE_IO;
    }
    
    // Read profiles
    for (int i = 0; i < ctx->num_profiles; i++) {
        if (fread(&ctx->profiles[i], sizeof(struct v_euicc_profile), 1, fp) != 1) {
            fclose(fp);
            return V_EUICC_ERROR_FILE_IO;
        }
        
        // Read profile data if present
        if (ctx->profiles[i].profile_data_len > 0) {
            ctx->profiles[i].profile_data = malloc(ctx->profiles[i].profile_data_len);
            if (!ctx->profiles[i].profile_data) {
                fclose(fp);
                return V_EUICC_ERROR_MEMORY_ALLOCATION;
            }
            
            if (fread(ctx->profiles[i].profile_data, 1, ctx->profiles[i].profile_data_len, fp) 
                != ctx->profiles[i].profile_data_len) {
                free(ctx->profiles[i].profile_data);
                fclose(fp);
                return V_EUICC_ERROR_FILE_IO;
            }
            ctx->profiles[i].allocated = true;
        }
    }
    
    fclose(fp);
    return V_EUICC_SUCCESS;
}

int v_euicc_save_storage(struct v_euicc_ctx *ctx) {
    if (!ctx) return V_EUICC_ERROR_INVALID_PARAMETER;
    
    FILE *fp = fopen(ctx->storage_file, "wb");
    if (!fp) return V_EUICC_ERROR_FILE_IO;
    
    // Write number of profiles
    if (fwrite(&ctx->num_profiles, sizeof(int), 1, fp) != 1) {
        fclose(fp);
        return V_EUICC_ERROR_FILE_IO;
    }
    
    // Write enabled profile index
    if (fwrite(&ctx->enabled_profile_index, sizeof(int), 1, fp) != 1) {
        fclose(fp);
        return V_EUICC_ERROR_FILE_IO;
    }
    
    // Write profiles
    for (int i = 0; i < ctx->num_profiles; i++) {
        if (fwrite(&ctx->profiles[i], sizeof(struct v_euicc_profile), 1, fp) != 1) {
            fclose(fp);
            return V_EUICC_ERROR_FILE_IO;
        }
        
        // Write profile data if present
        if (ctx->profiles[i].profile_data_len > 0 && ctx->profiles[i].profile_data) {
            if (fwrite(ctx->profiles[i].profile_data, 1, ctx->profiles[i].profile_data_len, fp)
                != ctx->profiles[i].profile_data_len) {
                fclose(fp);
                return V_EUICC_ERROR_FILE_IO;
            }
        }
    }
    
    fclose(fp);
    return V_EUICC_SUCCESS;
}

// Certificate management (stub implementations for now)
int v_euicc_cert_init(struct v_euicc_ctx *ctx) {
    if (!ctx) return V_EUICC_ERROR_INVALID_PARAMETER;
    
    // Initialize certificate context based on configuration
    // This is where we'll implement flexible certificate handling
    // including PQC support in the future
    
    ctx->cert_ctx = NULL; // Will be implemented with actual crypto library
    
    if (ctx->config.debug_mode) {
        printf("v-euicc: Certificate context initialized (type: %d)\n", 
               ctx->config.euicc_cert.type);
    }
    
    return V_EUICC_SUCCESS;
}

void v_euicc_cert_fini(struct v_euicc_ctx *ctx) {
    if (!ctx || !ctx->cert_ctx) return;
    
    // Clean up certificate context
    free(ctx->cert_ctx);
    ctx->cert_ctx = NULL;
}

int v_euicc_cert_sign(struct v_euicc_ctx *ctx, const uint8_t *data, size_t data_len __attribute__((unused)), 
                      uint8_t **signature, size_t *sig_len) {
    if (!ctx || !data || !signature || !sig_len) {
        return V_EUICC_ERROR_INVALID_PARAMETER;
    }
    
    // Stub implementation - will be replaced with actual crypto
    *sig_len = 64; // Typical ECDSA signature length
    *signature = malloc(*sig_len);
    if (!*signature) return V_EUICC_ERROR_MEMORY_ALLOCATION;
    
    // Generate dummy signature for now
    memset(*signature, 0xAA, *sig_len);
    
    return V_EUICC_SUCCESS;
}

int v_euicc_cert_verify(struct v_euicc_ctx *ctx, const uint8_t *data, size_t data_len __attribute__((unused)),
                        const uint8_t *signature, size_t sig_len __attribute__((unused))) {
    if (!ctx || !data || !signature) {
        return V_EUICC_ERROR_INVALID_PARAMETER;
    }
    
    // Stub implementation - will be replaced with actual crypto
    return V_EUICC_SUCCESS;
}

// Core initialization and cleanup
int v_euicc_init(struct v_euicc_ctx *ctx, const char *config_file) {
    if (!ctx) return V_EUICC_ERROR_INVALID_PARAMETER;
    
    memset(ctx, 0, sizeof(struct v_euicc_ctx));
    
    // Load configuration
    int ret = v_euicc_load_config(&ctx->config, config_file);
    if (ret != V_EUICC_SUCCESS) return ret;
    
    // Initialize mutex
    if (pthread_mutex_init(&ctx->mutex, NULL) != 0) {
        return V_EUICC_ERROR_UNKNOWN;
    }
    
    // Set up storage file path
    snprintf(ctx->storage_file, sizeof(ctx->storage_file), 
             "%s/profiles.dat", ctx->config.storage_path);
    
    // Create storage directory if it doesn't exist
    mkdir(ctx->config.storage_path, 0755);
    
    // Load stored profiles
    ret = v_euicc_load_storage(ctx);
    if (ret != V_EUICC_SUCCESS) {
        pthread_mutex_destroy(&ctx->mutex);
        return ret;
    }
    
    // Initialize certificate context
    ret = v_euicc_cert_init(ctx);
    if (ret != V_EUICC_SUCCESS) {
        pthread_mutex_destroy(&ctx->mutex);
        return ret;
    }
    
    // Generate initial challenge
    srand(time(NULL));
    for (int i = 0; i < 16; i++) {
        ctx->euicc_challenge[i] = rand() % 256;
    }
    
    ctx->enabled_profile_index = -1;
    ctx->running = false;
    ctx->comm_fd = -1;
    
    if (ctx->config.debug_mode) {
        printf("v-euicc: Initialized with EID: %s\n", ctx->config.eid);
    }
    
    // Set global context
    g_v_euicc_ctx = ctx;
    
    return V_EUICC_SUCCESS;
}

void v_euicc_fini(struct v_euicc_ctx *ctx) {
    if (!ctx) return;
    
    // Stop communication if running
    if (ctx->running) {
        v_euicc_stop(ctx);
    }
    
    // Save current state
    v_euicc_save_storage(ctx);
    
    // Clean up certificate context
    v_euicc_cert_fini(ctx);
    
    // Free profile data
    for (int i = 0; i < ctx->num_profiles; i++) {
        if (ctx->profiles[i].allocated && ctx->profiles[i].profile_data) {
            free(ctx->profiles[i].profile_data);
        }
    }
    
    // Free configuration strings
    if (ctx->config.euicc_cert.cert_path) free(ctx->config.euicc_cert.cert_path);
    if (ctx->config.euicc_cert.private_key_path) free(ctx->config.euicc_cert.private_key_path);
    if (ctx->config.euicc_cert.ca_cert_path) free(ctx->config.euicc_cert.ca_cert_path);
    if (ctx->config.eum_cert.cert_path) free(ctx->config.eum_cert.cert_path);
    if (ctx->config.eum_cert.private_key_path) free(ctx->config.eum_cert.private_key_path);
    if (ctx->config.eum_cert.ca_cert_path) free(ctx->config.eum_cert.ca_cert_path);
    
    // Clean up transaction ID
    if (ctx->current_transaction_id) {
        free(ctx->current_transaction_id);
    }
    
    // Destroy mutex
    pthread_mutex_destroy(&ctx->mutex);
    
    // Clear global context
    if (g_v_euicc_ctx == ctx) {
        g_v_euicc_ctx = NULL;
    }
    
    if (ctx->config.debug_mode) {
        printf("v-euicc: Finalized\n");
    }
}

int v_euicc_start(struct v_euicc_ctx *ctx) {
    if (!ctx) return V_EUICC_ERROR_INVALID_PARAMETER;
    
    if (ctx->running) {
        return V_EUICC_SUCCESS; // Already running
    }
    
    // Initialize communication if needed
    int ret = v_euicc_comm_init(ctx);
    if (ret != V_EUICC_SUCCESS) return ret;
    
    ctx->running = true;
    
    if (ctx->config.debug_mode) {
        printf("v-euicc: Started\n");
    }
    
    return V_EUICC_SUCCESS;
}

void v_euicc_stop(struct v_euicc_ctx *ctx) {
    if (!ctx || !ctx->running) return;
    
    ctx->running = false;
    
    // Stop communication
    v_euicc_comm_fini(ctx);
    
    if (ctx->config.debug_mode) {
        printf("v-euicc: Stopped\n");
    }
}

// Communication layer stubs
int v_euicc_comm_init(struct v_euicc_ctx *ctx) {
    if (!ctx) return V_EUICC_ERROR_INVALID_PARAMETER;
    
    // Communication initialization is handled by the server application
    // This is a stub for the library interface
    return V_EUICC_SUCCESS;
}

void v_euicc_comm_fini(struct v_euicc_ctx *ctx) {
    if (!ctx) return;
    
    // Communication cleanup is handled by the server application
    // This is a stub for the library interface
    if (ctx->comm_fd >= 0) {
        close(ctx->comm_fd);
        ctx->comm_fd = -1;
    }
}

void *v_euicc_comm_thread(void *arg) {
    struct v_euicc_ctx *ctx = (struct v_euicc_ctx *)arg;
    
    if (!ctx) return NULL;
    
    // This would implement the communication thread
    // For now, it's a stub since the server handles communication
    
    return NULL;
}

// Stub implementations for ES10a operations
int v_euicc_es10a_get_configured_addresses(struct v_euicc_ctx *ctx, 
                                           char **default_smdp, char **root_smds) {
    if (!ctx || !default_smdp || !root_smds) {
        return V_EUICC_ERROR_INVALID_PARAMETER;
    }
    
    *default_smdp = strdup(ctx->config.default_smdp_address);
    *root_smds = strdup(ctx->config.root_smds_address);
    
    return V_EUICC_SUCCESS;
}

int v_euicc_es10a_set_default_smdp(struct v_euicc_ctx *ctx, const char *smdp_address) {
    if (!ctx || !smdp_address) return V_EUICC_ERROR_INVALID_PARAMETER;
    
    strncpy(ctx->config.default_smdp_address, smdp_address, 
            sizeof(ctx->config.default_smdp_address) - 1);
    ctx->config.default_smdp_address[sizeof(ctx->config.default_smdp_address) - 1] = '\0';
    
    return V_EUICC_SUCCESS;
}

// Continue with other ES10b and ES10c operations...
// (These will be implemented in separate files for better organization) 