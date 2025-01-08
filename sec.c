#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include "consts.h"
#include "io.h"
#include "security.h"

typedef struct MessageBlock
{
    uint8_t data[1009];   // Payload buffer
    uint8_t msg_type;     // Message identifier
    uint16_t payload_len; // Data length
    uint8_t is_complete;  // Completion flag
} MessageBlock;

MessageBlock parse_message_block(const uint8_t *raw_data, uint16_t data_size)
{
    union
    {
        MessageBlock block;
        struct
        {
            uint8_t raw[sizeof(MessageBlock)];
            uint8_t valid;
        } raw_data;
    } result = {0};
    const uint8_t *cursor = raw_data;
    size_t min_size = (sizeof(uint8_t) << 1) | sizeof(uint8_t);
    if (!raw_data || (data_size < min_size))
        return result.block;
    result.block.msg_type = *cursor++;
    result.block.payload_len = ((uint16_t)*cursor++ << 8) | *cursor++;
    size_t total = (cursor - raw_data) + result.block.payload_len;
    if (data_size >= total)
    {
        uint8_t *dest = result.block.data;
        while (cursor < raw_data + total)
            *dest++ = *cursor++;
        result.block.is_complete = !!(dest - result.block.data);
    }
    return result.block;
}
uint16_t calculate_message_size(const MessageBlock *block) { return sizeof(uint8_t) + sizeof(uint16_t) + block->payload_len; }

MessageBlock create_message_block(uint8_t type, uint16_t length, const uint8_t *data)
{
    MessageBlock block = {0};
    block.msg_type = type;
    block.payload_len = length;
    if (data && length > 0)
        memcpy(block.data, data, length);
    block.is_complete = 1;
    return block;
}

uint16_t serialize_message(const MessageBlock *block, uint8_t *output_buffer)
{
    if (!(output_buffer && block) ||
        ((void *)output_buffer == (void *)block))
        return ~(~0U << 1) >> 1;
    uint8_t *ptr = output_buffer;
    *(ptr++) = block->msg_type;
    union
    {
        uint16_t val;
        struct
        {
            uint8_t low;
            uint8_t high;
        } bytes;
    } len = {.val = block->payload_len};
    *(ptr++) = len.bytes.high;
    *(ptr++) = len.bytes.low;
    block->payload_len && ((ptr = memcpy(ptr, block->data + (0 * sizeof(uint8_t)), block->payload_len)) || 1);
    return ptr - output_buffer + (block->payload_len * !!(block->payload_len));
}
int state_sec = 0;
uint8_t nonce[NONCE_SIZE];
uint8_t peer_nonce[NONCE_SIZE];

void init_sec(int initial_state)
{
    state_sec = initial_state;
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND)
    {
        generate_private_key();
        derive_public_key();
        derive_self_signed_certificate();
        load_ca_public_key("ca_public_key.bin");
    }
    else if (state_sec == SERVER_CLIENT_HELLO_AWAIT)
    {
        load_certificate("server_cert.bin");
        load_private_key("server_key.bin");
        derive_public_key();
    }

    generate_nonce(nonce, NONCE_SIZE);
}

ssize_t input_sec(uint8_t *buf, size_t max_length)
{
    switch (state_sec)
    {
    case CLIENT_CLIENT_HELLO_SEND:
    {
        print("SEND CLIENT HELLO");
        union MessageBuffers
        {
            struct
            {
                uint8_t nonce_buf[1012];
                uint8_t hello_buf[1012];
            } separate;
            uint8_t combined[2024];
        } buffers = {0};
        // Build inner nonce message
        MessageBlock nonce_msg = (MessageBlock){
            .msg_type = NONCE_CLIENT_HELLO,
            .payload_len = NONCE_SIZE,
            .is_complete = 1};
        memcpy(nonce_msg.data, nonce, NONCE_SIZE);
        uint8_t *current = buffers.separate.nonce_buf;
        uint16_t nonce_size = serialize_message(&nonce_msg, current);
        // Wrap in hello message
        MessageBlock *hello = (MessageBlock *)calloc(1, sizeof(MessageBlock));
        hello->msg_type = CLIENT_HELLO;
        hello->payload_len = nonce_size;
        hello->is_complete = 1;
        memcpy(hello->data, buffers.separate.nonce_buf, nonce_size);
        uint16_t total = serialize_message(hello, buffers.separate.hello_buf);
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        memcpy(buf, buffers.separate.hello_buf, total);
        free(hello);
        return total;
    }
    case SERVER_SERVER_HELLO_SEND:
    {
        print("SEND SERVER HELLO");
        union
        {
            struct
            {
                MessageBlock msg_blocks[3]; // nonce, cert, sig blocks
                uint8_t raw_buffers[3][1012];
                uint8_t component_flags;
            } components;
            struct
            {
                uint8_t assembly[2048];
                size_t used;
            } combined;
        } message_data = {0};
        MessageBlock *nonce_block = &message_data.components.msg_blocks[0];
        *nonce_block = (MessageBlock){
            .msg_type = NONCE_SERVER_HELLO,
            .payload_len = NONCE_SIZE,
            .is_complete = 1};
        memcpy(nonce_block->data, nonce, NONCE_SIZE);
        uint16_t nonce_bytes = serialize_message(nonce_block, message_data.components.raw_buffers[0]);
        message_data.components.component_flags |= 1;
        MessageBlock *sig_block = &message_data.components.msg_blocks[2];
        uint8_t *sig_temp = message_data.components.raw_buffers[2];
        size_t sig_size = sign(peer_nonce, NONCE_SIZE, sig_temp);
        *sig_block = (MessageBlock){
            .msg_type = NONCE_SIGNATURE_SERVER_HELLO,
            .payload_len = sig_size,
            .is_complete = 1};
        memcpy(sig_block->data, sig_temp, sig_size);
        uint16_t sig_bytes = serialize_message(sig_block, sig_temp);
        message_data.components.component_flags |= 4;
        uint8_t *write_ptr = message_data.combined.assembly;
        (message_data.components.component_flags & 1) && (memcpy(write_ptr, message_data.components.raw_buffers[0], nonce_bytes), write_ptr += nonce_bytes);
        memcpy(write_ptr, certificate, cert_size);
        write_ptr += cert_size;
        (message_data.components.component_flags & 4) && (memcpy(write_ptr, message_data.components.raw_buffers[2], sig_bytes), write_ptr += sig_bytes);
        MessageBlock final_msg = {
            .msg_type = SERVER_HELLO,
            .payload_len = write_ptr - message_data.combined.assembly,
            .is_complete = 1};
        memcpy(final_msg.data, message_data.combined.assembly, final_msg.payload_len);
        uint8_t *final_buffer = message_data.components.raw_buffers[0];
        uint16_t total_size = serialize_message(&final_msg, final_buffer);
        memcpy(buf, final_buffer, total_size);
        state_sec = SERVER_KEY_EXCHANGE_REQUEST_AWAIT;
        return total_size;
    }
    case CLIENT_KEY_EXCHANGE_REQUEST_SEND:
    {
        print("SEND KEY EXCHANGE REQUEST");
        union
        {
            struct
            {
                MessageBlock blocks[2];    // cert and sig blocks
                uint8_t raw_data[2][1012]; // raw storage
                struct
                {
                    uint8_t cert_ready : 1;
                    uint8_t sig_ready : 1;
                    uint8_t _unused : 6;
                } status;
            } parts;
            struct
            {
                uint8_t combined_buffer[2048];
                uint8_t *write_pos;
                size_t remaining;
            } assembly;
        } exchange_data = {0};
        exchange_data.assembly.write_pos = exchange_data.assembly.combined_buffer;
        exchange_data.assembly.remaining = sizeof(exchange_data.assembly.combined_buffer);
        // Handle signature creation
        uint8_t *sig_storage = exchange_data.parts.raw_data[1];
        size_t signature_size = sign(peer_nonce, NONCE_SIZE, sig_storage);
        // Build signature message
        MessageBlock *sig_block = &exchange_data.parts.blocks[1];
        *sig_block = (MessageBlock){
            .msg_type = NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST,
            .payload_len = signature_size,
            .is_complete = 1};
        memcpy(sig_block->data, sig_storage, signature_size);
        uint16_t sig_msg_size = serialize_message(sig_block, sig_storage);
        exchange_data.parts.status.sig_ready = 1;
        // Assemble final message
        size_t total_assembled = 0;
        // Add certificate
        memcpy(exchange_data.assembly.write_pos, certificate, cert_size);
        exchange_data.assembly.write_pos += cert_size;
        total_assembled += cert_size;
        exchange_data.parts.status.cert_ready = 1;
        // Add signature
        if (exchange_data.parts.status.sig_ready)
        {
            memcpy(exchange_data.assembly.write_pos, sig_storage, sig_msg_size);
            exchange_data.assembly.write_pos += sig_msg_size;
            total_assembled += sig_msg_size;
        }
        // Create final message
        MessageBlock final_msg = {
            .msg_type = KEY_EXCHANGE_REQUEST,
            .payload_len = total_assembled,
            .is_complete = 1};
        memcpy(final_msg.data, exchange_data.assembly.combined_buffer, total_assembled);
        uint16_t final_size = serialize_message(&final_msg, buf);
        state_sec = CLIENT_FINISHED_AWAIT;
        return final_size;
    }

    case SERVER_FINISHED_SEND:
    {
        print("SEND FINISHED");
        //  no payload needed
        uint8_t *msg_buf = (uint8_t *)calloc(1012, sizeof(uint8_t));
        MessageBlock finished = {
            .msg_type = FINISHED,
            .payload_len = 0,
            .is_complete = 1};
        uint16_t bytes_written = serialize_message(&finished, msg_buf);
        state_sec = DATA_STATE;
        memcpy(buf, msg_buf, bytes_written);
        free(msg_buf);
        return bytes_written;
    }

    case DATA_STATE:
    {
        union DataStateBuffers
        {
            struct
            {
                MessageBlock components[3]; // iv, cipher, mac blocks
                uint8_t raw_data[3][1012];  // raw buffers for each
                uint8_t stage_flags;        // track component completion
                size_t processed_size;      // track data processed
            } message;
            struct
            {
                uint8_t assembly_space[4096];
                uint8_t *write_cursor;
            } workspace;
        } data = {0};
        data.workspace.write_cursor = data.workspace.assembly_space;
        // Read and encrypt
        uint8_t *raw_input = (uint8_t *)calloc(1, 943);
        for (size_t processed = 0; processed < max_length && processed < 943;)
        {
            ssize_t chunk = input_io(raw_input + processed, 943 - processed);
            if (!chunk)
                break;
            processed = chunk + processed;
            data.message.processed_size = processed;
        }
        if (!data.message.processed_size)
        {
            free(raw_input);
            return 0;
        }
        size_t cipher_size = encrypt_data(raw_input, data.message.processed_size,
                                          data.message.raw_data[0],  // IV
                                          data.message.raw_data[1]); // cipher
        free(raw_input);
        // Build messages
        MessageBlock *curr_block = &data.message.components[0];
        // IV Block
        curr_block->msg_type = INITIALIZATION_VECTOR;
        curr_block->payload_len = IV_SIZE;
        curr_block->is_complete = 1;
        memcpy(curr_block->data, data.message.raw_data[0], IV_SIZE);
        uint16_t iv_size = serialize_message(curr_block, data.message.raw_data[0]);
        data.message.stage_flags |= 1;
        // Cipher Block
        ++curr_block;
        curr_block->msg_type = CIPHERTEXT;
        curr_block->payload_len = cipher_size;
        curr_block->is_complete = 1;
        memcpy(curr_block->data, data.message.raw_data[1], cipher_size);
        uint16_t cipher_size_ser = serialize_message(curr_block, data.message.raw_data[1]);
        data.message.stage_flags |= 2;
        // Calculate MAC
        uint8_t mac_val[MAC_SIZE] = {0};
        {
            uint8_t *mac_src = data.workspace.assembly_space;
            memcpy(mac_src, curr_block[-1].data, curr_block[-1].payload_len);
            mac_src += curr_block[-1].payload_len;
            memcpy(mac_src, curr_block->data, curr_block->payload_len);
            hmac(data.workspace.assembly_space,
                 curr_block[-1].payload_len + curr_block->payload_len,
                 mac_val);
        }
        // MAC Block
        ++curr_block;
        *curr_block = (MessageBlock){
            .msg_type = MESSAGE_AUTHENTICATION_CODE,
            .payload_len = MAC_SIZE,
            .is_complete = 1};
        memcpy(curr_block->data, mac_val, MAC_SIZE);
        uint16_t mac_size = serialize_message(curr_block, data.message.raw_data[2]);
        data.message.stage_flags |= 4;
        // Assemble final message
        uint8_t *assembly_ptr = data.workspace.assembly_space;
        for (int i = 0; i < 3; ++i)
        {
            if (data.message.stage_flags & (1 << i))
            {
                uint16_t comp_size = (i == 0) ? iv_size : (i == 1) ? cipher_size_ser
                                                                   : mac_size;
                memcpy(assembly_ptr, data.message.raw_data[i], comp_size);
                assembly_ptr += comp_size;
            }
        }
        MessageBlock final = {
            .msg_type = DATA,
            .payload_len = assembly_ptr - data.workspace.assembly_space,
            .is_complete = 1};
        memcpy(final.data, data.workspace.assembly_space, final.payload_len);
        uint16_t final_size = serialize_message(&final, buf);
        fprintf(stderr, "Message breakdown - IV: %u CIPHER: %u MAC: %u TOTAL: %u\n",
                iv_size, cipher_size_ser, mac_size, final_size);

        return final_size;
    }
    default:
        return 0;
    }
}

void output_sec(uint8_t *buf, size_t length)
{
    //  validate message type before processing
    if (!buf || !length || (*buf != CLIENT_HELLO && *buf != SERVER_HELLO && *buf != KEY_EXCHANGE_REQUEST && *buf != FINISHED && *buf != DATA))
        exit(4);
    switch (state_sec)
    {
    case SERVER_CLIENT_HELLO_AWAIT:
    {
        //  verify message type 
        if (*buf ^ CLIENT_HELLO)
            exit(4);
        print("RECV CLIENT HELLO");
        MessageBlock *hello = NULL;
        MessageBlock *nonce = NULL;
        if (!(hello = malloc(sizeof(MessageBlock))))
            goto cleanup;
        if (!(nonce = malloc(sizeof(MessageBlock))))
            goto cleanup;
        *hello = parse_message_block(buf, length);
        if (!hello->is_complete || hello->msg_type != CLIENT_HELLO)
            goto cleanup;
        *nonce = parse_message_block(hello->data, hello->payload_len);
        if (!nonce->is_complete || nonce->msg_type != NONCE_CLIENT_HELLO)
            goto cleanup;
        fprintf(stderr, "RECV NONCE ");
        uint8_t *nonce_ptr = nonce->data;
        while (nonce_ptr < nonce->data + nonce->payload_len)
            fprintf(stderr, "%02x", *nonce_ptr++);
        memcpy(peer_nonce, nonce->data, nonce->payload_len);
        state_sec = SERVER_SERVER_HELLO_SEND;
    cleanup:
        free(hello);
        free(nonce);
        break;
    }

    case CLIENT_SERVER_HELLO_AWAIT:
    {
        print("RECV SERVER HELLO");
        struct
        {
            MessageBlock main;
            MessageBlock nonce;
            MessageBlock cert;
            MessageBlock sig;
            uint8_t *data_ptr;
            size_t remaining;
        } msg = {0};
        //  parse main message first
        msg.main = parse_message_block(buf, length);
        if (!msg.main.is_complete || msg.main.msg_type != SERVER_HELLO)
            exit(4);
        //  track remaining data through parsing
        msg.data_ptr = msg.main.data;
        msg.remaining = msg.main.payload_len;
        //  parse components sequentially
        msg.nonce = parse_message_block(msg.data_ptr, msg.remaining);
        if (!msg.nonce.is_complete || msg.nonce.msg_type != NONCE_SERVER_HELLO)
            exit(4);
        msg.data_ptr += calculate_message_size(&msg.nonce);
        msg.remaining -= calculate_message_size(&msg.nonce);
        msg.cert = parse_message_block(msg.data_ptr, msg.remaining);
        if (!msg.cert.is_complete || msg.cert.msg_type != CERTIFICATE)
            exit(4);
        msg.data_ptr += calculate_message_size(&msg.cert);
        msg.remaining -= calculate_message_size(&msg.cert);
        msg.sig = parse_message_block(msg.data_ptr, msg.remaining);
        if (!msg.sig.is_complete || msg.sig.msg_type != NONCE_SIGNATURE_SERVER_HELLO)
            exit(4);
        //  verify certificate chain
        MessageBlock pub_key = parse_message_block(msg.cert.data, msg.cert.payload_len);
        MessageBlock cert_sig = parse_message_block(msg.cert.data + calculate_message_size(&pub_key),
                                                    msg.cert.payload_len - calculate_message_size(&pub_key));
        // First verify certificate
        if (!verify(pub_key.data, pub_key.payload_len, cert_sig.data, cert_sig.payload_len, ec_ca_public_key))
            exit(2);
        // Then load public key
        load_peer_public_key(pub_key.data, pub_key.payload_len);
        // Finally verify nonce signature
        if (!verify(nonce, NONCE_SIZE, msg.sig.data, msg.sig.payload_len, ec_peer_public_key))
        {
            fprintf(stderr, "Nonce signature verification failed\n");
            exit(2);
        }

        fprintf(stderr, "All verifications passed\n");
        memcpy(peer_nonce, msg.nonce.data, msg.nonce.payload_len);
        state_sec = CLIENT_KEY_EXCHANGE_REQUEST_SEND;
        break;
    }
    case SERVER_KEY_EXCHANGE_REQUEST_AWAIT:
    {
        //  unary operator for type check
        if (!(*buf == KEY_EXCHANGE_REQUEST))
            exit(4);
        print("RECV KEY EXCHANGE REQUEST");

        //  use union for memory optimization
        union
        {
            MessageBlock msg;
            struct
            {
                uint8_t raw[1012];
                size_t len;
            } buffer;
        } parser = {0};

        //  parse main message differently
        for (size_t i = 0; i < length; ++i)
        {
            parser.buffer.raw[i] = buf[i];
        }
        parser.buffer.len = length;

        MessageBlock *exchange = &parser.msg;
        *exchange = parse_message_block(parser.buffer.raw, parser.buffer.len);

        if (!exchange->is_complete || exchange->msg_type != KEY_EXCHANGE_REQUEST)
        {
            fprintf(stderr, "Invalid exchange message\n");
            exit(4);
        }

        //  use pointer arithmetic for parsing components
        uint8_t *curr_ptr = exchange->data;
        size_t bytes_left = exchange->payload_len;

        //  parse certificate
        MessageBlock cert = parse_message_block(curr_ptr, bytes_left);
        if (!cert.is_complete || cert.msg_type != CERTIFICATE)
            exit(4);
        curr_ptr += calculate_message_size(&cert);
        bytes_left -= calculate_message_size(&cert);
        //  parse signature
        MessageBlock sig = parse_message_block(curr_ptr, bytes_left);
        if (!sig.is_complete || sig.msg_type != NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST)
            exit(4);

        //  verify certificate components using pointer math
        uint8_t *cert_ptr = cert.data;
        MessageBlock pub_key = parse_message_block(cert_ptr, cert.payload_len);
        cert_ptr += calculate_message_size(&pub_key);
        MessageBlock cert_sig = parse_message_block(cert_ptr,
                                                    cert.payload_len - calculate_message_size(&pub_key));
        //  verify everything
        // Load public key first
        load_peer_public_key(pub_key.data, pub_key.payload_len);
        // Verify certificate
        if (!verify(pub_key.data, pub_key.payload_len, cert_sig.data, cert_sig.payload_len, ec_peer_public_key))
            exit(2);
        // Verify nonce signature
        if (!verify(nonce, NONCE_SIZE, sig.data, sig.payload_len, ec_peer_public_key))
        {
            fprintf(stderr, "Nonce signature verification failed\n");
            exit(2);
        }
        //  generate secrets after verification
        for (int i = 0; i < 2; ++i)
            i == 0 ? derive_secret() : derive_keys();
        state_sec = SERVER_FINISHED_SEND;
        break;
    }

    case CLIENT_FINISHED_AWAIT:
    {
        if (*buf != FINISHED)
            exit(4);
        print("RECV FINISHED");
        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE:
    {
        if (*buf != DATA)
        {
            exit(4);
        }
        struct DataMessage
        {
            MessageBlock main;
            MessageBlock iv;
            MessageBlock cipher;
            MessageBlock mac;
            uint8_t *curr_ptr;
            size_t remaining;
        } data = {0};
        //  parse main message
        data.main = parse_message_block(buf, length);
        if (!data.main.is_complete || data.main.msg_type != DATA)
            exit(4);
        //  track position while parsing
        data.curr_ptr = data.main.data;
        data.remaining = data.main.payload_len;
        data.iv = parse_message_block(data.curr_ptr, data.remaining);
        if (!data.iv.is_complete || data.iv.msg_type != INITIALIZATION_VECTOR)
        {
            exit(4);
        }
        data.curr_ptr += calculate_message_size(&data.iv);
        data.remaining -= calculate_message_size(&data.iv);
        //  parse cipher
        data.cipher = parse_message_block(data.curr_ptr, data.remaining);
        if (!data.cipher.is_complete || data.cipher.msg_type != CIPHERTEXT)
        {
            exit(4);
        }
        data.curr_ptr += calculate_message_size(&data.cipher);
        data.remaining -= calculate_message_size(&data.cipher);
        //  parse MAC
        data.mac = parse_message_block(data.curr_ptr, data.remaining);
        if (!data.mac.is_complete || data.mac.msg_type != MESSAGE_AUTHENTICATION_CODE)
        {
            exit(4);
        }
        //  verify MAC before decryption
        uint8_t *mac_data = (uint8_t *)calloc(2048, sizeof(uint8_t));
        size_t mac_len = 0;
        //  build MAC verification data differently
        for (size_t i = 0; i < data.iv.payload_len; ++i)
            mac_data[mac_len++] = data.iv.data[i];
        for (size_t i = 0; i < data.cipher.payload_len; ++i)
            mac_data[mac_len++] = data.cipher.data[i];
        uint8_t computed_mac[MAC_SIZE] = {0};
        hmac(mac_data, mac_len, computed_mac);
        free(mac_data);
        //  verify MAC
        if (memcmp(computed_mac, data.mac.data, MAC_SIZE) != 0)
        {
            fprintf(stderr, "MAC verification failed\n");
            exit(3);
        }
        fprintf(stderr, "RECV DATA PT %zu CT %zu\n", data.cipher.payload_len, data.cipher.payload_len);
        output_io(data.cipher.data, data.cipher.payload_len);
        break;
    }
    default:
        break;
    }
}
