#include "../include/v_euicc_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

// CRC32 implementation for message validation
static uint32_t crc32_table[256];
static bool crc32_table_initialized = false;

static void init_crc32_table(void) {
    if (crc32_table_initialized) return;
    
    uint32_t polynomial = 0xEDB88320;
    for (int i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 8; j > 0; j--) {
            if (crc & 1) {
                crc = (crc >> 1) ^ polynomial;
            } else {
                crc >>= 1;
            }
        }
        crc32_table[i] = crc;
    }
    crc32_table_initialized = true;
}

uint32_t v_euicc_calculate_checksum(const void *data, size_t data_len) {
    // Use simple checksum for now (same as driver)
    const uint8_t *buf = (const uint8_t *)data;
    uint32_t sum = 0;
    
    for (size_t i = 0; i < data_len; i++) {
        sum += buf[i];
    }
    
    return sum;
}

struct v_euicc_message *v_euicc_create_message(enum v_euicc_message_type type, 
                                               uint32_t sequence,
                                               const void *data, 
                                               uint32_t data_len) {
    if (data_len > V_EUICC_MAX_MESSAGE_SIZE - sizeof(struct v_euicc_message_header)) {
        return NULL;
    }
    
    size_t total_size = sizeof(struct v_euicc_message_header) + data_len;
    struct v_euicc_message *message = malloc(total_size);
    if (!message) return NULL;
    
    message->header.magic = V_EUICC_MESSAGE_MAGIC;
    message->header.version = V_EUICC_PROTOCOL_VERSION;
    message->header.type = type;
    message->header.sequence = sequence;
    message->header.data_length = data_len;
    message->header.checksum = data_len > 0 ? v_euicc_calculate_checksum(data, data_len) : 0;
    
    if (data_len > 0 && data) {
        memcpy(message->data, data, data_len);
    }
    
    return message;
}

int v_euicc_parse_message(const uint8_t *buffer, size_t buffer_len,
                          struct v_euicc_message **message) {
    if (!buffer || !message || buffer_len < sizeof(struct v_euicc_message_header)) {
        return -1;
    }
    
    const struct v_euicc_message_header *header = 
        (const struct v_euicc_message_header *)buffer;
    
    // Validate header
    if (header->magic != V_EUICC_MESSAGE_MAGIC ||
        header->version != V_EUICC_PROTOCOL_VERSION ||
        header->data_length > V_EUICC_MAX_MESSAGE_SIZE ||
        buffer_len < sizeof(struct v_euicc_message_header) + header->data_length) {
        return -1;
    }
    
    // Verify checksum if there's data
    if (header->data_length > 0) {
        const uint8_t *data = buffer + sizeof(struct v_euicc_message_header);
        uint32_t calculated_checksum = v_euicc_calculate_checksum(data, header->data_length);
        if (calculated_checksum != header->checksum) {
            return -1;
        }
    }
    
    // Allocate and copy message
    size_t total_size = sizeof(struct v_euicc_message_header) + header->data_length;
    *message = malloc(total_size);
    if (!*message) return -1;
    
    memcpy(*message, buffer, total_size);
    
    return 0;
}

void v_euicc_free_message(struct v_euicc_message *message) {
    if (message) {
        free(message);
    }
}

bool v_euicc_validate_message(const struct v_euicc_message *message) {
    if (!message) return false;
    
    if (message->header.magic != V_EUICC_MESSAGE_MAGIC ||
        message->header.version != V_EUICC_PROTOCOL_VERSION ||
        message->header.data_length > V_EUICC_MAX_MESSAGE_SIZE) {
        return false;
    }
    
    if (message->header.data_length > 0) {
        uint32_t calculated_checksum = v_euicc_calculate_checksum(message->data, 
                                                                  message->header.data_length);
        if (calculated_checksum != message->header.checksum) {
            return false;
        }
    }
    
    return true;
}

int v_euicc_send_message(int fd, const struct v_euicc_message *message) {
    if (fd < 0 || !message) return -1;
    
    if (!v_euicc_validate_message(message)) return -1;
    
    size_t total_size = sizeof(struct v_euicc_message_header) + message->header.data_length;
    ssize_t sent = send(fd, message, total_size, 0);
    
    return (sent == (ssize_t)total_size) ? 0 : -1;
}

int v_euicc_receive_message(int fd, struct v_euicc_message **message) {
    if (fd < 0 || !message) return -1;
    
    // First, receive the header
    struct v_euicc_message_header header;
    ssize_t received = recv(fd, &header, sizeof(header), MSG_WAITALL);
    if (received != sizeof(header)) {
        return -1;
    }
    
    // Validate header
    if (header.magic != V_EUICC_MESSAGE_MAGIC ||
        header.version != V_EUICC_PROTOCOL_VERSION ||
        header.data_length > V_EUICC_MAX_MESSAGE_SIZE) {
        return -1;
    }
    
    // Allocate complete message
    size_t total_size = sizeof(struct v_euicc_message_header) + header.data_length;
    *message = malloc(total_size);
    if (!*message) return -1;
    
    // Copy header
    (*message)->header = header;
    
    // Receive data if present
    if (header.data_length > 0) {
        received = recv(fd, (*message)->data, header.data_length, MSG_WAITALL);
        if (received != (ssize_t)header.data_length) {
            free(*message);
            *message = NULL;
            return -1;
        }
        
        // Verify checksum
        uint32_t calculated_checksum = v_euicc_calculate_checksum((*message)->data, 
                                                                  header.data_length);
        if (calculated_checksum != header.checksum) {
            free(*message);
            *message = NULL;
            return -1;
        }
    }
    
    return 0;
}

// Connection management
int v_euicc_connection_init(struct v_euicc_connection *conn) {
    if (!conn) return -1;
    
    memset(conn, 0, sizeof(struct v_euicc_connection));
    conn->state = V_EUICC_STATE_DISCONNECTED;
    conn->fd = -1;
    conn->next_sequence = 1;
    
    return 0;
}

void v_euicc_connection_cleanup(struct v_euicc_connection *conn) {
    if (!conn) return;
    
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
    
    conn->state = V_EUICC_STATE_DISCONNECTED;
    memset(conn->open_channels, 0, sizeof(conn->open_channels));
    conn->num_open_channels = 0;
}

int v_euicc_connection_open(struct v_euicc_connection *conn __attribute__((unused)), 
                            const char *address __attribute__((unused)), 
                            int port __attribute__((unused))) {
    // This would implement the connection logic based on address type
    // For now, this is a placeholder
    return -1; // Not implemented
}

void v_euicc_connection_close(struct v_euicc_connection *conn) {
    if (!conn) return;
    
    v_euicc_connection_cleanup(conn);
}

// Channel management
int v_euicc_allocate_channel(struct v_euicc_connection *conn) {
    if (!conn) return -1;
    
    for (int i = 1; i < 16; i++) { // Channel 0 is reserved
        if (!(conn->open_channels[i / 8] & (1 << (i % 8)))) {
            conn->open_channels[i / 8] |= (1 << (i % 8));
            conn->num_open_channels++;
            return i;
        }
    }
    
    return -1; // No available channels
}

void v_euicc_release_channel(struct v_euicc_connection *conn, uint8_t channel) {
    if (!conn || channel >= 16) return;
    
    if (conn->open_channels[channel / 8] & (1 << (channel % 8))) {
        conn->open_channels[channel / 8] &= ~(1 << (channel % 8));
        conn->num_open_channels--;
    }
}

bool v_euicc_is_channel_open(struct v_euicc_connection *conn, uint8_t channel) {
    if (!conn || channel >= 16) return false;
    
    return (conn->open_channels[channel / 8] & (1 << (channel % 8))) != 0;
}

// Request/Response helpers
int v_euicc_send_request_and_wait_response(struct v_euicc_connection *conn,
                                           enum v_euicc_message_type req_type,
                                           const void *req_data, uint32_t req_data_len,
                                           struct v_euicc_message **response,
                                           int timeout_ms __attribute__((unused))) {
    if (!conn || conn->fd < 0 || !response) return -1;
    
    // Create request message
    uint32_t sequence = conn->next_sequence++;
    struct v_euicc_message *request = v_euicc_create_message(req_type, sequence, 
                                                             req_data, req_data_len);
    if (!request) return -1;
    
    // Send request
    int result = v_euicc_send_message(conn->fd, request);
    v_euicc_free_message(request);
    
    if (result < 0) return -1;
    
    // Wait for response (simplified - should implement timeout)
    result = v_euicc_receive_message(conn->fd, response);
    if (result < 0) return -1;
    
    // Verify sequence number
    if ((*response)->header.sequence != sequence) {
        v_euicc_free_message(*response);
        *response = NULL;
        return -1;
    }
    
    return 0;
}

// Error handling
const char *v_euicc_protocol_error_string(enum v_euicc_protocol_error error) {
    switch (error) {
        case V_EUICC_PROTOCOL_SUCCESS:
            return "Success";
        case V_EUICC_PROTOCOL_ERROR_INVALID_MESSAGE:
            return "Invalid message";
        case V_EUICC_PROTOCOL_ERROR_UNSUPPORTED_VERSION:
            return "Unsupported protocol version";
        case V_EUICC_PROTOCOL_ERROR_INVALID_CHANNEL:
            return "Invalid channel";
        case V_EUICC_PROTOCOL_ERROR_CHANNEL_ALREADY_OPEN:
            return "Channel already open";
        case V_EUICC_PROTOCOL_ERROR_NO_CHANNEL_AVAILABLE:
            return "No channel available";
        case V_EUICC_PROTOCOL_ERROR_APDU_ERROR:
            return "APDU error";
        case V_EUICC_PROTOCOL_ERROR_INTERNAL_ERROR:
            return "Internal error";
        case V_EUICC_PROTOCOL_ERROR_NOT_CONNECTED:
            return "Not connected";
        case V_EUICC_PROTOCOL_ERROR_TIMEOUT:
            return "Timeout";
        default:
            return "Unknown error";
    }
}

// Debugging and logging
void v_euicc_dump_message(const struct v_euicc_message *message) {
    if (!message) {
        printf("Message: NULL\n");
        return;
    }
    
    printf("Message:\n");
    printf("  Magic: 0x%08X\n", message->header.magic);
    printf("  Version: %u\n", message->header.version);
    printf("  Type: %u\n", message->header.type);
    printf("  Sequence: %u\n", message->header.sequence);
    printf("  Data Length: %u\n", message->header.data_length);
    printf("  Checksum: 0x%08X\n", message->header.checksum);
    
    if (message->header.data_length > 0) {
        printf("  Data: ");
        for (uint32_t i = 0; i < message->header.data_length && i < 32; i++) {
            printf("%02X ", message->data[i]);
        }
        if (message->header.data_length > 32) {
            printf("...");
        }
        printf("\n");
    }
}

void v_euicc_log_protocol_error(enum v_euicc_protocol_error error, const char *context) {
    printf("Protocol Error: %s", v_euicc_protocol_error_string(error));
    if (context) {
        printf(" (Context: %s)", context);
    }
    printf("\n");
} 