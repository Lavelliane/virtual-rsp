#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Protocol version for compatibility
#define V_EUICC_PROTOCOL_VERSION 1

// Maximum message size
#define V_EUICC_MAX_MESSAGE_SIZE 65536

// Message types for communication between lpac driver and v-euicc
enum v_euicc_message_type {
    // Connection management
    V_EUICC_MSG_CONNECT = 0x01,
    V_EUICC_MSG_DISCONNECT = 0x02,
    V_EUICC_MSG_PING = 0x03,
    
    // Channel management
    V_EUICC_MSG_OPEN_CHANNEL = 0x10,
    V_EUICC_MSG_CLOSE_CHANNEL = 0x11,
    
    // APDU transmission
    V_EUICC_MSG_TRANSMIT_APDU = 0x20,
    
    // Response types
    V_EUICC_MSG_RESPONSE = 0x80,
    V_EUICC_MSG_ERROR = 0x81,
    
    // Status and information
    V_EUICC_MSG_STATUS = 0x90,
    V_EUICC_MSG_INFO = 0x91
};

// Error codes for protocol communication
enum v_euicc_protocol_error {
    V_EUICC_PROTOCOL_SUCCESS = 0,
    V_EUICC_PROTOCOL_ERROR_INVALID_MESSAGE = 1,
    V_EUICC_PROTOCOL_ERROR_UNSUPPORTED_VERSION = 2,
    V_EUICC_PROTOCOL_ERROR_INVALID_CHANNEL = 3,
    V_EUICC_PROTOCOL_ERROR_CHANNEL_ALREADY_OPEN = 4,
    V_EUICC_PROTOCOL_ERROR_NO_CHANNEL_AVAILABLE = 5,
    V_EUICC_PROTOCOL_ERROR_APDU_ERROR = 6,
    V_EUICC_PROTOCOL_ERROR_INTERNAL_ERROR = 7,
    V_EUICC_PROTOCOL_ERROR_NOT_CONNECTED = 8,
    V_EUICC_PROTOCOL_ERROR_TIMEOUT = 9
};

// Message header structure
struct v_euicc_message_header {
    uint32_t magic;           // Magic number for validation
    uint16_t version;         // Protocol version
    uint16_t type;            // Message type (v_euicc_message_type)
    uint32_t sequence;        // Sequence number for request/response matching
    uint32_t data_length;     // Length of the data following the header
    uint32_t checksum;        // CRC32 checksum of data
} __attribute__((packed));

// Magic number for message validation
#define V_EUICC_MESSAGE_MAGIC 0x56455543  // "VEUC" in little endian

// Connect message data
struct v_euicc_connect_data {
    uint16_t client_version;
    char client_name[64];
} __attribute__((packed));

// Open channel message data
struct v_euicc_open_channel_data {
    uint8_t aid_length;
    uint8_t aid[16];  // Application ID
} __attribute__((packed));

// Close channel message data
struct v_euicc_close_channel_data {
    uint8_t channel;
} __attribute__((packed));

// APDU transmission message data
struct v_euicc_transmit_apdu_data {
    uint8_t channel;
    uint16_t apdu_length;
    uint8_t apdu[];  // Variable length APDU data
} __attribute__((packed));

// Response message data (generic)
struct v_euicc_response_data {
    uint16_t error_code;     // 0 for success, error code otherwise
    uint16_t data_length;    // Length of response data
    uint8_t data[];          // Variable length response data
} __attribute__((packed));

// Status message data
struct v_euicc_status_data {
    uint8_t num_profiles;
    uint8_t enabled_profile_index;
    uint8_t num_open_channels;
    uint8_t available_channels;
    uint32_t uptime_seconds;
    char eid[33];            // EID as null-terminated string
} __attribute__((packed));

// Complete message structure
struct v_euicc_message {
    struct v_euicc_message_header header;
    uint8_t data[];
} __attribute__((packed));

// Function declarations for protocol handling

// Message creation and parsing
struct v_euicc_message *v_euicc_create_message(enum v_euicc_message_type type, 
                                               uint32_t sequence,
                                               const void *data, 
                                               uint32_t data_len);
int v_euicc_parse_message(const uint8_t *buffer, size_t buffer_len,
                          struct v_euicc_message **message);
void v_euicc_free_message(struct v_euicc_message *message);

// Message validation
bool v_euicc_validate_message(const struct v_euicc_message *message);
uint32_t v_euicc_calculate_checksum(const void *data, size_t data_len);

// Utility functions for message handling
int v_euicc_send_message(int fd, const struct v_euicc_message *message);
int v_euicc_receive_message(int fd, struct v_euicc_message **message);

// Protocol state machine helpers
enum v_euicc_connection_state {
    V_EUICC_STATE_DISCONNECTED,
    V_EUICC_STATE_CONNECTING,
    V_EUICC_STATE_CONNECTED,
    V_EUICC_STATE_ERROR
};

struct v_euicc_connection {
    enum v_euicc_connection_state state;
    int fd;
    uint32_t next_sequence;
    uint8_t open_channels[16];  // Bitmap of open channels
    uint8_t num_open_channels;
};

// Connection management
int v_euicc_connection_init(struct v_euicc_connection *conn);
void v_euicc_connection_cleanup(struct v_euicc_connection *conn);
int v_euicc_connection_open(struct v_euicc_connection *conn, const char *address, int port);
void v_euicc_connection_close(struct v_euicc_connection *conn);

// Channel management
int v_euicc_allocate_channel(struct v_euicc_connection *conn);
void v_euicc_release_channel(struct v_euicc_connection *conn, uint8_t channel);
bool v_euicc_is_channel_open(struct v_euicc_connection *conn, uint8_t channel);

// Request/Response helpers
int v_euicc_send_request_and_wait_response(struct v_euicc_connection *conn,
                                           enum v_euicc_message_type req_type,
                                           const void *req_data, uint32_t req_data_len,
                                           struct v_euicc_message **response,
                                           int timeout_ms);

// Error handling
const char *v_euicc_protocol_error_string(enum v_euicc_protocol_error error);

// Debugging and logging
void v_euicc_dump_message(const struct v_euicc_message *message);
void v_euicc_log_protocol_error(enum v_euicc_protocol_error error, const char *context); 