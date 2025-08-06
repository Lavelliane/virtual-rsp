#include "../include/v_euicc.h"
#include "../include/v_euicc_protocol.h"
#include "../include/v_euicc_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <getopt.h>

// Forward declaration
static void log_apdu_detailed(const char *direction, const uint8_t *apdu, size_t length, const char *description);

// Global variables
static struct v_euicc_ctx g_ctx;
static struct v_euicc_ecdsa_context g_crypto_ctx;
static bool g_running = false;
static int g_server_fd = -1;

// Signal handler for graceful shutdown
static void signal_handler(int signum) {
    printf("\nReceived signal %d, shutting down gracefully...\n", signum);
    g_running = false;
    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }
    
    // Cleanup crypto context
    v_euicc_crypto_cleanup(&g_crypto_ctx);
}

// Detailed APDU logging function
static void log_apdu_detailed(const char *direction, const uint8_t *apdu, size_t length, const char *description) {
    if (!g_ctx.config.debug_mode) return;
    
    printf("\n=== %s APDU Analysis ===\n", direction);
    printf("Description: %s\n", description);
    printf("Length: %zu bytes\n", length);
    
    if (length > 0) {
        printf("Raw APDU: ");
        for (size_t i = 0; i < length; i++) {
            printf("%02X ", apdu[i]);
            if ((i + 1) % 16 == 0) printf("\n          ");
        }
        printf("\n");
        
        if (length >= 4) {
            printf("APDU Header Analysis:\n");
            printf("  CLA: 0x%02X", apdu[0]);
            if ((apdu[0] & 0x0F) != 0) {
                printf(" (Channel: %d)", apdu[0] & 0x0F);
            }
            printf("\n");
            
            printf("  INS: 0x%02X", apdu[1]);
            switch (apdu[1]) {
                case 0xE0: printf(" (ES10a/ES10b command)"); break;
                case 0xE2: printf(" (ES10c command)"); break;
                case 0xCA: printf(" (GET DATA)"); break;
                case 0xA4: printf(" (SELECT)"); break;
                default: printf(" (Unknown instruction)"); break;
            }
            printf("\n");
            
            printf("  P1: 0x%02X, P2: 0x%02X\n", apdu[2], apdu[3]);
            
            if (length > 4) {
                printf("  Lc: %d (data length)\n", apdu[4]);
                
                if (length > 5 && apdu[4] > 0) {
                    printf("Command Data: ");
                    for (int i = 0; i < apdu[4] && i < 32; i++) {
                        printf("%02X ", apdu[5 + i]);
                    }
                    if (apdu[4] > 32) printf("...");
                    printf("\n");
                    
                    // Analyze SGP.22 command data
                    if (apdu[1] == 0xE2 && apdu[2] == 0x91 && apdu[3] == 0x00) {
                        printf("  -> ES10c.GetEID command detected\n");
                        if (length > 5) {
                            printf("  -> Command data contains ASN.1 structure\n");
                            const uint8_t *data = &apdu[5];
                            if (data[0] == 0xBF && data[1] == 0x3E) {
                                printf("  -> BF3E tag found (GetEIDRequest)\n");
                            }
                        }
                    }
                    else if (apdu[1] == 0xE0) {
                        printf("  -> ES10a/ES10b command detected\n");
                        if (length > 5) {
                            const uint8_t *data = &apdu[5];
                            if (data[0] == 0xBF && data[1] == 0x20) {
                                printf("  -> BF20 tag found (GetEUICCInfo1)\n");
                            }
                            else if (data[0] == 0xBF && data[1] == 0x2E) {
                                printf("  -> BF2E tag found (GetEUICCChallenge)\n");
                            }
                            else if (data[0] == 0xBF && data[1] == 0x38) {
                                printf("  -> BF38 tag found (AuthenticateServer)\n");
                            }
                            else if (data[0] == 0xBF && data[1] == 0x22) {
                                printf("  -> BF22 tag found (GetEUICCInfo2)\n");
                            }
                        }
                    }
                }
            }
        }
    }
    printf("========================\n");
}

// Process client messages
static int handle_client_message(int client_fd, struct v_euicc_message *message) {
    enum v_euicc_protocol_error error_code = V_EUICC_PROTOCOL_SUCCESS;
    uint8_t *response_data = NULL;
    uint32_t response_data_len = 0;
    
    if (g_ctx.config.debug_mode) {
        printf("Processing message type %d from client\n", message->header.type);
    }
    
    switch (message->header.type) {
        case V_EUICC_MSG_CONNECT: {
            struct v_euicc_connect_data *connect_data = 
                (struct v_euicc_connect_data *)message->data;
            
            if (g_ctx.config.debug_mode) {
                printf("Client connected: %s (version %d)\n", 
                       connect_data->client_name, connect_data->client_version);
            }
            
            // Create success response
            struct v_euicc_response_data success_response = {
                .error_code = 0,
                .data_length = 0
            };
            response_data = malloc(sizeof(success_response));
            if (response_data) {
                memcpy(response_data, &success_response, sizeof(success_response));
                response_data_len = sizeof(success_response);
            } else {
                error_code = V_EUICC_PROTOCOL_ERROR_INTERNAL_ERROR;
            }
            break;
        }
        
        case V_EUICC_MSG_DISCONNECT: {
            if (g_ctx.config.debug_mode) {
                printf("Client disconnecting\n");
            }
            
            struct v_euicc_response_data success_response = {
                .error_code = 0,
                .data_length = 0
            };
            response_data = malloc(sizeof(success_response));
            if (response_data) {
                memcpy(response_data, &success_response, sizeof(success_response));
                response_data_len = sizeof(success_response);
            }
            break;
        }
        
        case V_EUICC_MSG_PING: {
            if (g_ctx.config.debug_mode) {
                printf("Ping received\n");
            }
            
            struct v_euicc_response_data success_response = {
                .error_code = 0,
                .data_length = 0
            };
            response_data = malloc(sizeof(success_response));
            if (response_data) {
                memcpy(response_data, &success_response, sizeof(success_response));
                response_data_len = sizeof(success_response);
            }
            break;
        }
        
        case V_EUICC_MSG_OPEN_CHANNEL: {
            struct v_euicc_open_channel_data *open_data = 
                (struct v_euicc_open_channel_data *)message->data;
            
            if (g_ctx.config.debug_mode) {
                printf("Opening logical channel for AID length %d: ", open_data->aid_length);
                for (int i = 0; i < open_data->aid_length; i++) {
                    printf("%02X", open_data->aid[i]);
                }
                printf("\n");
            }
            
            // Check for eUICC AID: A0000005591010FFFFFFFF8900000100
            static const uint8_t euicc_aid[] = {0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 
                                               0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00};
            
            if (open_data->aid_length == sizeof(euicc_aid) && 
                memcmp(open_data->aid, euicc_aid, sizeof(euicc_aid)) == 0) {
                
                if (g_ctx.config.debug_mode) {
                    printf("Recognized eUICC AID, opening logical channel\n");
                }
                
                struct v_euicc_response_data success_response = {
                    .error_code = 0,
                    .data_length = 0
                };
                response_data = malloc(sizeof(success_response));
                if (response_data) {
                    memcpy(response_data, &success_response, sizeof(success_response));
                    response_data_len = sizeof(success_response);
                }
            } else {
                if (g_ctx.config.debug_mode) {
                    printf("Unknown AID, rejecting channel open\n");
                }
                error_code = V_EUICC_PROTOCOL_ERROR_INVALID_CHANNEL;
            }
            break;
        }
        
        case V_EUICC_MSG_CLOSE_CHANNEL: {
            struct v_euicc_close_channel_data *close_data = 
                (struct v_euicc_close_channel_data *)message->data;
            
            if (g_ctx.config.debug_mode) {
                printf("Closing logical channel %d\n", close_data->channel);
            }
            
            struct v_euicc_response_data success_response = {
                .error_code = 0,
                .data_length = 0
            };
            response_data = malloc(sizeof(success_response));
            if (response_data) {
                memcpy(response_data, &success_response, sizeof(success_response));
                response_data_len = sizeof(success_response);
            }
            break;
        }
        
        case V_EUICC_MSG_TRANSMIT_APDU: {
            struct v_euicc_transmit_apdu_data *transmit_data = 
                (struct v_euicc_transmit_apdu_data *)message->data;
            
            // Log incoming APDU with detailed analysis
            log_apdu_detailed("INCOMING", transmit_data->apdu, transmit_data->apdu_length, 
                            "Command from lpac client");
            
            if (g_ctx.config.debug_mode) {
                printf("Processing APDU on channel %d (length %d)\n", 
                       transmit_data->channel, transmit_data->apdu_length);
            }
            
            // Handle basic eUICC APDUs
            uint8_t apdu_response[256];
            size_t response_len = 0;
            
            if (transmit_data->apdu_length >= 4) {
                uint8_t cla = transmit_data->apdu[0];
                uint8_t ins = transmit_data->apdu[1];
                uint8_t p1 = transmit_data->apdu[2];
                uint8_t p2 = transmit_data->apdu[3];
                
                if (g_ctx.config.debug_mode) {
                    printf("APDU command: CLA=%02X INS=%02X P1=%02X P2=%02X\n", cla, ins, p1, p2);
                }
                
                // Handle SGP.22 commands
                if (ins == 0xE2 && p1 == 0x91 && p2 == 0x00) {
                    // Parse ASN.1 command data to determine specific operation
                    if (transmit_data->apdu_length > 5) {
                        uint8_t tag1 = transmit_data->apdu[5];
                        uint8_t tag2 = (transmit_data->apdu_length > 6) ? transmit_data->apdu[6] : 0x00;
                        uint16_t full_tag = (tag1 << 8) | tag2;
                        
                        if (g_ctx.config.debug_mode) {
                            printf("SGP.22 command with tag: %02X%02X\n", tag1, tag2);
                        }
                        
                        if (full_tag == 0xBF20) {
                            // ES10b.GetEUICCInfo1 request
                            if (g_ctx.config.debug_mode) {
                                printf("ES10b.GetEUICCInfo1 command detected\n");
                            }
                            
                            // Use crypto function to create proper EUICCInfo1
                            uint8_t *euicc_info1_data;
                            size_t euicc_info1_len;
                            
                            if (v_euicc_create_euicc_info1(&g_crypto_ctx, &euicc_info1_data, &euicc_info1_len) == 0) {
                                // Copy the response
                                if (euicc_info1_len + 2 <= sizeof(apdu_response)) {
                                    memcpy(apdu_response, euicc_info1_data, euicc_info1_len);
                                    apdu_response[euicc_info1_len] = 0x90; // SW1
                                    apdu_response[euicc_info1_len + 1] = 0x00; // SW2
                                    response_len = euicc_info1_len + 2;
                                } else {
                                    apdu_response[0] = 0x6C;
                                    apdu_response[1] = 0x00; // Wrong length
                                    response_len = 2;
                                }
                                free(euicc_info1_data);
                            } else {
                                apdu_response[0] = 0x6F;
                                apdu_response[1] = 0x00; // No precise diagnosis
                                response_len = 2;
                            }
                            
                        } else if (full_tag == 0xBF2E) {
                            // ES10b.GetEUICCChallenge request
                            if (g_ctx.config.debug_mode) {
                                printf("ES10b.GetEUICCChallenge command detected\n");
                                printf("Generating cryptographically secure 16-byte eUICC challenge...\n");
                            }
                            
                            // Generate cryptographically secure eUICC challenge
                            uint8_t euicc_challenge[V_EUICC_CHALLENGE_LENGTH];
                            if (v_euicc_generate_challenge(euicc_challenge) != 0) {
                                if (g_ctx.config.debug_mode) {
                                    printf("❌ Failed to generate eUICC challenge\n");
                                }
                                apdu_response[0] = 0x6F;
                                apdu_response[1] = 0x00; // No precise diagnosis
                                response_len = 2;
                                break;
                            }
                            
                            if (g_ctx.config.debug_mode) {
                                printf("✅ eUICC challenge generated successfully\n");
                                printf("Challenge bytes: ");
                                for (int i = 0; i < V_EUICC_CHALLENGE_LENGTH; i++) {
                                    printf("%02X ", euicc_challenge[i]);
                                }
                                printf("\n");
                            }
                            
                            // Store challenge in both contexts
                            memcpy(g_ctx.euicc_challenge, euicc_challenge, V_EUICC_CHALLENGE_LENGTH);
                            memcpy(g_crypto_ctx.current_challenge, euicc_challenge, V_EUICC_CHALLENGE_LENGTH);
                            
                            if (g_ctx.config.debug_mode) {
                                printf("Challenge stored in global contexts\n");
                            }
                            
                            int pos = 0;
                            
                            // BF2E tag (GetEuiccChallengeResponse)
                            apdu_response[pos++] = 0xBF;
                            apdu_response[pos++] = 0x2E;
                            apdu_response[pos++] = 0x10; // Length (16 bytes for challenge)
                            
                            // euiccChallenge (16 bytes)
                            for (int i = 0; i < 16; i++) {
                                apdu_response[pos++] = euicc_challenge[i];
                            }
                            
                            apdu_response[pos++] = 0x90; // SW1
                            apdu_response[pos++] = 0x00; // SW2
                            response_len = pos;
                            
                            if (g_ctx.config.debug_mode) {
                                printf("Generated GetEUICCChallenge response (%zu bytes)\n", response_len);
                                printf("Response includes: BF2E tag + 16-byte challenge + SW=9000\n");
                            }
                            
                        } else if (full_tag == 0xBF38) {
                            // ES10b.AuthenticateServer request
                            if (g_ctx.config.debug_mode) {
                                printf("ES10b.AuthenticateServer command detected\n");
                            }
                            
                            // Parse the incoming AuthenticateServerRequest
                            uint8_t *server_signed1 = NULL;
                            size_t server_signed1_len = 0;
                            uint8_t *server_signature1 = NULL;
                            size_t server_signature1_len = 0;
                            uint8_t *euicc_ci_pkid = NULL;
                            size_t euicc_ci_pkid_len = 0;
                            uint8_t *server_certificate = NULL;
                            size_t server_certificate_len = 0;
                            
                            // Parse the request (simplified for now)
                            if (v_euicc_parse_authenticate_server_request(
                                transmit_data->apdu + 5, transmit_data->apdu_length - 5,
                                &server_signed1, &server_signed1_len,
                                &server_signature1, &server_signature1_len,
                                &euicc_ci_pkid, &euicc_ci_pkid_len,
                                &server_certificate, &server_certificate_len) == 0) {
                                
                                if (g_ctx.config.debug_mode) {
                                    printf("AuthenticateServer: Parsed request successfully\n");
                                }
                                
                                // Extract transaction ID and server challenge from serverSigned1
                                // For now, use dummy values - in real implementation, parse from serverSigned1
                                uint8_t dummy_transaction_id[] = {0x01, 0x02, 0x03, 0x04};
                                uint8_t dummy_server_challenge[V_EUICC_CHALLENGE_LENGTH];
                                v_euicc_generate_challenge(dummy_server_challenge);
                                
                                // Store in crypto context
                                memcpy(g_crypto_ctx.transaction_id, dummy_transaction_id, sizeof(dummy_transaction_id));
                                g_crypto_ctx.transaction_id_length = sizeof(dummy_transaction_id);
                                memcpy(g_crypto_ctx.server_challenge, dummy_server_challenge, V_EUICC_CHALLENGE_LENGTH);
                                
                                // Create ECDSA-signed AuthenticateServerResponse
                                uint8_t *auth_response_data = NULL;
                                size_t auth_response_len = 0;
                                const char *server_address = "testsmdpplus1.example.com";
                                
                                if (v_euicc_create_authenticate_server_response(&g_crypto_ctx,
                                    (const uint8_t *)server_address, strlen(server_address),
                                    &auth_response_data, &auth_response_len) == 0) {
                                    
                                    if (g_ctx.config.debug_mode) {
                                        printf("AuthenticateServer: Generated ECDSA signature successfully\n");
                                    }
                                    
                                    // Copy response data
                                    if (auth_response_len + 2 <= sizeof(apdu_response)) {
                                        memcpy(apdu_response, auth_response_data, auth_response_len);
                                        apdu_response[auth_response_len] = 0x90; // SW1
                                        apdu_response[auth_response_len + 1] = 0x00; // SW2
                                        response_len = auth_response_len + 2;
                                    } else {
                                        apdu_response[0] = 0x6C;
                                        apdu_response[1] = 0x00; // Wrong length
                                        response_len = 2;
                                    }
                                    free(auth_response_data);
                                } else {
                                    if (g_ctx.config.debug_mode) {
                                        printf("AuthenticateServer: Failed to create ECDSA response\n");
                                    }
                                    apdu_response[0] = 0x6F;
                                    apdu_response[1] = 0x00; // No precise diagnosis
                                    response_len = 2;
                                }
                                
                                // Clean up parsed data
                                free(server_signed1);
                                free(server_signature1);
                                free(euicc_ci_pkid);
                                free(server_certificate);
                            } else {
                                if (g_ctx.config.debug_mode) {
                                    printf("AuthenticateServer: Failed to parse request\n");
                                }
                                apdu_response[0] = 0x6A;
                                apdu_response[1] = 0x80; // Incorrect parameters in data field
                                response_len = 2;
                            }
                            
                            if (g_ctx.config.debug_mode) {
                                printf("AuthenticateServer: Returning simplified success response\n");
                                printf("Note: Full implementation requires ECDSA signature operations\n");
                            }
                            
                        } else if (full_tag == 0xBF3E) {
                            // ES10c GetEID command
                            if (g_ctx.config.debug_mode) {
                                printf("ES10c GetEID command detected\n");
                            }
                            
                            // Create EID response
                            int pos = 0;
                            
                            // BF3E tag (GetEIDResponse)
                            apdu_response[pos++] = 0xBF;
                            apdu_response[pos++] = 0x3E;
                            apdu_response[pos++] = 0x12; // Length (18 bytes: 5A tag + 10 data + SW)
                            
                            // 5A tag (EID tag) 
                            apdu_response[pos++] = 0x5A;
                            apdu_response[pos++] = 0x10; // Length (16 bytes)
                            
                            // Copy EID bytes directly (EID is already in binary format)
                            for (int i = 0; i < 16; i++) {
                                apdu_response[pos++] = g_crypto_ctx.eid[i];
                            }
                            
                            apdu_response[pos++] = 0x90; // SW1
                            apdu_response[pos++] = 0x00; // SW2
                            response_len = pos;
                            
                        } else if (full_tag == 0xBF22) {
                            // ES10c.GetEUICCInfo2 command
                            if (g_ctx.config.debug_mode) {
                                printf("ES10c.GetEUICCInfo2 command detected\n");
                            }
                            
                            // Create comprehensive EUICCInfo2 response
                            int pos = 0;
                            
                            // BF22 tag (EUICCInfo2)
                            apdu_response[pos++] = 0xBF;
                            apdu_response[pos++] = 0x22;
                            
                            // Calculate content length (we'll update this)
                            int length_pos = pos++;
                            int content_start = pos;
                            
                            // Profile Version [1] (SIMAlliance Profile package version)
                            apdu_response[pos++] = 0x81; // Context tag [1]
                            apdu_response[pos++] = 0x03; // Length
                            apdu_response[pos++] = 0x02; // Version 2.1.0
                            apdu_response[pos++] = 0x01;
                            apdu_response[pos++] = 0x00;
                            
                            // SVN [2] (SGP.22 version)
                            apdu_response[pos++] = 0x82; // Context tag [2]
                            apdu_response[pos++] = 0x03; // Length
                            apdu_response[pos++] = 0x02; // Version 2.2.1
                            apdu_response[pos++] = 0x02;
                            apdu_response[pos++] = 0x01;
                            
                            // eUICC Firmware Version [3]
                            apdu_response[pos++] = 0x83; // Context tag [3]
                            apdu_response[pos++] = 0x03; // Length
                            apdu_response[pos++] = 0x01; // Version 1.0.0
                            apdu_response[pos++] = 0x00;
                            apdu_response[pos++] = 0x00;
                            
                            // Extended Card Resource [4]
                            apdu_response[pos++] = 0x84; // Context tag [4]
                            apdu_response[pos++] = 0x08; // Length
                            apdu_response[pos++] = 0x00; // Installed applications
                            apdu_response[pos++] = 0x01;
                            apdu_response[pos++] = 0x00; // Free non-volatile memory (1MB)
                            apdu_response[pos++] = 0x10;
                            apdu_response[pos++] = 0x00; // Free volatile memory (64KB)
                            apdu_response[pos++] = 0x01;
                            apdu_response[pos++] = 0x00;
                            apdu_response[pos++] = 0x00;
                            
                            // UICC Capability [5]
                            apdu_response[pos++] = 0x85; // Context tag [5]
                            apdu_response[pos++] = 0x01; // Length
                            apdu_response[pos++] = 0x07; // USIM + ISIM + contactless support
                            
                            // RSP Capability [8]
                            apdu_response[pos++] = 0x88; // Context tag [8]
                            apdu_response[pos++] = 0x01; // Length
                            apdu_response[pos++] = 0x1F; // All capabilities supported
                            
                            // euiccCiPKIdListForVerification [9]
                            apdu_response[pos++] = 0x89; // Context tag [9]
                            apdu_response[pos++] = 0x14; // Length (20 bytes for one PKID)
                            // Add CI PKID (20 bytes - SHA-1 of CI public key)
                            for (int i = 0; i < 20; i++) {
                                apdu_response[pos++] = 0x01 + i; // Dummy PKID
                            }
                            
                            // euiccCiPKIdListForSigning [10]
                            apdu_response[pos++] = 0x8A; // Context tag [10]
                            apdu_response[pos++] = 0x14; // Length (20 bytes for one PKID)
                            // Add CI PKID (20 bytes)
                            for (int i = 0; i < 20; i++) {
                                apdu_response[pos++] = 0x01 + i; // Same PKID as verification
                            }
                            
                            // eUICC Category [11] OPTIONAL
                            apdu_response[pos++] = 0x8B; // Context tag [11]
                            apdu_response[pos++] = 0x01; // Length
                            apdu_response[pos++] = 0x02; // mediumEuicc
                            
                            // PP Version (Protection Profile version)
                            apdu_response[pos++] = 0x03; // Version 1.0.0
                            apdu_response[pos++] = 0x01;
                            apdu_response[pos++] = 0x00;
                            apdu_response[pos++] = 0x00;
                            
                            // SAS Accreditation Number
                            const char *sas_number = "VIRTUAL-EUICC-001";
                            int sas_len = strlen(sas_number);
                            memcpy(&apdu_response[pos], sas_number, sas_len);
                            pos += sas_len;
                            
                            // Update content length
                            int content_length = pos - content_start;
                            apdu_response[length_pos] = content_length;
                            
                            // Add status words
                            apdu_response[pos++] = 0x90; // SW1
                            apdu_response[pos++] = 0x00; // SW2
                            response_len = pos;
                            
                            if (g_ctx.config.debug_mode) {
                                printf("Generated EUICCInfo2 response (%zu bytes)\n", response_len);
                            }
                        } else {
                            // Unknown SGP.22 command
                            if (g_ctx.config.debug_mode) {
                                printf("Unknown SGP.22 command tag: %04X\n", full_tag);
                            }
                            apdu_response[0] = 0x6A;
                            apdu_response[1] = 0x86; // Incorrect parameters
                            response_len = 2;
                        }
                    } else {
                        // No tag data available
                        apdu_response[0] = 0x6A;
                        apdu_response[1] = 0x87; // Lc inconsistent with P1-P2
                        response_len = 2;
                    }
                    
                } else if (ins == 0xCA) {
                    // Generic GET DATA command
                    if (g_ctx.config.debug_mode) {
                        printf("GET DATA command detected (P1=%02X P2=%02X)\n", p1, p2);
                    }
                    // Return minimal response
                    apdu_response[0] = 0x90;
                    apdu_response[1] = 0x00;
                    response_len = 2;
                    
                } else if (ins == 0xE0) {
                    // ES10a/ES10b command
                    if (g_ctx.config.debug_mode) {
                        printf("ES10a/ES10b command detected\n");
                    }
                    // Return success but no data for now
                    apdu_response[0] = 0x90;
                    apdu_response[1] = 0x00;
                    response_len = 2;
                    
                } else {
                    // Default success response for other commands
                    if (g_ctx.config.debug_mode) {
                        printf("Unknown command, returning success\n");
                    }
                    apdu_response[0] = 0x90;
                    apdu_response[1] = 0x00;
                    response_len = 2;
                }
            } else {
                // Invalid APDU
                apdu_response[0] = 0x6E;
                apdu_response[1] = 0x00;
                response_len = 2;
            }
            
            // Log outgoing APDU response with detailed analysis
            log_apdu_detailed("OUTGOING", apdu_response, response_len, 
                            "Response to lpac client");
            
            if (g_ctx.config.debug_mode) {
                printf("Sending APDU response: SW1=0x%02X SW2=0x%02X\n", 
                       apdu_response[response_len-2], apdu_response[response_len-1]);
            }
            
            size_t total_response_size = sizeof(struct v_euicc_response_data) + response_len;
            response_data = malloc(total_response_size);
            if (response_data) {
                struct v_euicc_response_data *resp = (struct v_euicc_response_data *)response_data;
                resp->error_code = 0;
                resp->data_length = response_len;
                memcpy(resp->data, apdu_response, response_len);
                response_data_len = total_response_size;
            } else {
                error_code = V_EUICC_PROTOCOL_ERROR_INTERNAL_ERROR;
            }
            break;
        }
        
        default:
            if (g_ctx.config.debug_mode) {
                printf("Unknown message type: %d\n", message->header.type);
            }
            error_code = V_EUICC_PROTOCOL_ERROR_INVALID_MESSAGE;
            break;
    }
    
    // Send response
    struct v_euicc_message *response;
    if (error_code != V_EUICC_PROTOCOL_SUCCESS) {
        // Send error response
        struct v_euicc_response_data error_response = {
            .error_code = error_code,
            .data_length = 0
        };
        response = v_euicc_create_message(V_EUICC_MSG_ERROR, message->header.sequence,
                                          &error_response, sizeof(error_response));
    } else {
        // Send success response
        response = v_euicc_create_message(V_EUICC_MSG_RESPONSE, message->header.sequence,
                                          response_data, response_data_len);
    }
    
    if (response_data) {
        free(response_data);
    }
    
    if (response) {
        int result = v_euicc_send_message(client_fd, response);
        v_euicc_free_message(response);
        return result;
    }
    
    return -1;
}

// Handle client connection
static void handle_client(int client_fd) {
    if (g_ctx.config.debug_mode) {
        printf("New client connected (fd: %d)\n", client_fd);
    }
    
    while (g_running) {
        struct v_euicc_message *message;
        int result = v_euicc_receive_message(client_fd, &message);
        
        if (result < 0) {
            if (g_ctx.config.debug_mode) {
                printf("Client disconnected or error receiving message\n");
            }
            break;
        }
        
        result = handle_client_message(client_fd, message);
        
        // Check for disconnect message
        if (message->header.type == V_EUICC_MSG_DISCONNECT) {
            v_euicc_free_message(message);
            break;
        }
        
        v_euicc_free_message(message);
        
        if (result < 0) {
            if (g_ctx.config.debug_mode) {
                printf("Error sending response to client\n");
            }
            break;
        }
    }
    
    close(client_fd);
    if (g_ctx.config.debug_mode) {
        printf("Client connection closed (fd: %d)\n", client_fd);
    }
}

// Start the server
static int start_server(struct v_euicc_ctx *ctx) {
    int server_fd;
    
    if (ctx->config.comm_method == V_EUICC_COMM_UNIX_SOCKET) {
        // Unix socket
        struct sockaddr_un addr;
        
        server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server_fd < 0) {
            perror("socket");
            return -1;
        }
        
        // Remove existing socket file
        unlink(ctx->config.comm_address);
        
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, ctx->config.comm_address, sizeof(addr.sun_path) - 1);
        
        if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind");
            close(server_fd);
            return -1;
        }
        
        printf("v-euicc server listening on Unix socket: %s\n", ctx->config.comm_address);
        
    } else {
        // TCP socket
        struct sockaddr_in addr;
        int opt = 1;
        
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            perror("socket");
            return -1;
        }
        
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            perror("setsockopt");
            close(server_fd);
            return -1;
        }
        
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(ctx->config.comm_port);
        
        if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind");
            close(server_fd);
            return -1;
        }
        
        printf("v-euicc server listening on TCP port: %d\n", ctx->config.comm_port);
    }
    
    if (listen(server_fd, 5) < 0) {
        perror("listen");
        close(server_fd);
        return -1;
    }
    
    g_server_fd = server_fd;
    ctx->comm_fd = server_fd;
    ctx->running = true;
    g_running = true;
    
    printf("Virtual eUICC server started with EID: %s\n", ctx->config.eid);
    
    return 0;
}

// Main server loop
static void run_server(struct v_euicc_ctx *ctx) {
    while (g_running) {
        int client_fd = accept(ctx->comm_fd, NULL, NULL);
        if (client_fd < 0) {
            if (g_running) {
                perror("accept");
            }
            continue;
        }
        
        // For simplicity, handle clients sequentially
        // In a production implementation, we'd use threads or async I/O
        handle_client(client_fd);
    }
}

// Print usage information
static void print_usage(const char *program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -c, --config FILE    Configuration file path\n");
    printf("  -a, --address ADDR   Communication address (socket path or IP)\n");
    printf("  -p, --port PORT      TCP port (default: 8765)\n");
    printf("  -t, --type TYPE      Connection type: unix|tcp (default: unix)\n");
    printf("  -d, --debug          Enable debug mode\n");
    printf("  -h, --help           Show this help message\n");
    printf("  -v, --version        Show version information\n");
    printf("\nExample:\n");
    printf("  %s --address /tmp/v-euicc.sock --debug\n", program_name);
    printf("  %s --type tcp --port 8765 --debug\n", program_name);
}

// Main function
int main(int argc, char *argv[]) {
    int ret;
    char *config_file = NULL;
    char *address = NULL;
    int port = 0;
    char *conn_type = NULL;
    bool debug_mode = false;
    
    static struct option long_options[] = {
        {"config", required_argument, 0, 'c'},
        {"address", required_argument, 0, 'a'},
        {"port", required_argument, 0, 'p'},
        {"type", required_argument, 0, 't'},
        {"debug", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "c:a:p:t:dhv", long_options, &option_index)) != -1) {
        switch (c) {
            case 'c':
                config_file = optarg;
                break;
            case 'a':
                address = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 't':
                conn_type = optarg;
                break;
            case 'd':
                debug_mode = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'v':
                printf("v-euicc version %d.%d.%d\n", 
                       V_EUICC_VERSION_MAJOR, V_EUICC_VERSION_MINOR, V_EUICC_VERSION_PATCH);
                return 0;
            case '?':
                print_usage(argv[0]);
                return 1;
            default:
                break;
        }
    }
    
    printf("Virtual eUICC Server v%d.%d.%d\n", 
           V_EUICC_VERSION_MAJOR, V_EUICC_VERSION_MINOR, V_EUICC_VERSION_PATCH);
    printf("Starting initialization...\n");
    
    // Initialize virtual eUICC
    ret = v_euicc_init(&g_ctx, config_file);
    if (ret != V_EUICC_SUCCESS) {
        fprintf(stderr, "Failed to initialize virtual eUICC: %d\n", ret);
        return 1;
    }
    
    // Initialize crypto context
    if (v_euicc_crypto_init(&g_crypto_ctx, "./certs") != 0) {
        fprintf(stderr, "Failed to initialize crypto context\n");
        return 1;
    }
    printf("ECDSA certificates loaded successfully\n");
    
    // Override configuration with command line options
    if (address) {
        strncpy(g_ctx.config.comm_address, address, sizeof(g_ctx.config.comm_address) - 1);
        g_ctx.config.comm_address[sizeof(g_ctx.config.comm_address) - 1] = '\0';
    }
    
    if (port > 0) {
        g_ctx.config.comm_port = port;
    }
    
    if (conn_type) {
        if (strcmp(conn_type, "tcp") == 0) {
            g_ctx.config.comm_method = V_EUICC_COMM_TCP_SOCKET;
        } else if (strcmp(conn_type, "unix") == 0) {
            g_ctx.config.comm_method = V_EUICC_COMM_UNIX_SOCKET;
        } else {
            fprintf(stderr, "Invalid connection type: %s (use 'unix' or 'tcp')\n", conn_type);
            v_euicc_fini(&g_ctx);
            return 1;
        }
    }
    
    if (debug_mode) {
        g_ctx.config.debug_mode = true;
    }
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Start server
    ret = start_server(&g_ctx);
    if (ret < 0) {
        fprintf(stderr, "Failed to start server\n");
        v_euicc_fini(&g_ctx);
        return 1;
    }
    
    // Run main server loop
    run_server(&g_ctx);
    
    // Cleanup
    printf("Shutting down...\n");
    
    if (g_ctx.config.comm_method == V_EUICC_COMM_UNIX_SOCKET) {
        unlink(g_ctx.config.comm_address);
    }
    
    v_euicc_fini(&g_ctx);
    
    printf("Virtual eUICC server terminated.\n");
    return 0;
} 