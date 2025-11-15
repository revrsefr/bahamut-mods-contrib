#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "send.h"
#include "sbuf.h"
#include "h.h"
#include "hooks.h"

#include <openssl/sha.h>

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_PROTOCOL "irc"

#define WS_HANDSHAKE_OK 0
#define WS_HANDSHAKE_FAIL 1
#define WS_HANDSHAKE_UNSUPPORTED_VERSION 2
#define WS_HANDSHAKE_BAD_KEY 3

extern aClient me;

typedef struct
{
    char   *data;
    size_t  len;
    size_t  cap;
} ws_buffer;

typedef struct
{
    aClient *client;
    int      handshake_complete;
    int      continuation;
    ws_buffer handshake;
    ws_buffer frame_in;
    ws_buffer fragment;
    ws_buffer line_accum;
    ws_buffer pending_lines;
    ws_buffer sendbuf;
    char    *pending_buf;
    size_t   pending_len;
    int      pending_busy;
} ws_state;

static void *preaccess_hook = NULL;

static void ws_buffer_init(ws_buffer *buf)
{
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
}

static void ws_buffer_free(ws_buffer *buf)
{
    if (buf->data)
        MyFree(buf->data);
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
}

static int ws_buffer_reserve(ws_buffer *buf, size_t needed)
{
    if (needed <= buf->cap)
        return 0;

    size_t newcap = buf->cap ? buf->cap : 256;
    while (newcap < needed)
    {
        if (newcap > SIZE_MAX / 2)
            newcap = needed;
        else
            newcap *= 2;
    }

    char *tmp = (char *) MyRealloc(buf->data, newcap);
    if (!tmp)
        return -1;

    buf->data = tmp;
    buf->cap = newcap;
    return 0;
}

static int ws_buffer_append(ws_buffer *buf, const char *data, size_t len)
{
    if (len == 0)
        return 0;
    if (ws_buffer_reserve(buf, buf->len + len + 1) != 0)
        return -1;
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    buf->data[buf->len] = '\0';
    return 0;
}

static void ws_buffer_clear(ws_buffer *buf)
{
    buf->len = 0;
    if (buf->data)
        buf->data[0] = '\0';
}

static void ws_buffer_consume(ws_buffer *buf, size_t consumed)
{
    if (consumed >= buf->len)
    {
        ws_buffer_clear(buf);
        return;
    }
    memmove(buf->data, buf->data + consumed, buf->len - consumed);
    buf->len -= consumed;
    buf->data[buf->len] = '\0';
}

static void ws_base64_encode(const unsigned char *input, size_t len, char *out, size_t out_size)
{
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t needed = 4 * ((len + 2) / 3);
    size_t i = 0;
    size_t j = 0;

    if (out_size <= needed)
        return;

    while (i + 2 < len)
    {
        uint32_t triple = ((uint32_t)input[i] << 16) | ((uint32_t)input[i + 1] << 8) | input[i + 2];
        out[j++] = table[(triple >> 18) & 0x3F];
        out[j++] = table[(triple >> 12) & 0x3F];
        out[j++] = table[(triple >> 6) & 0x3F];
        out[j++] = table[triple & 0x3F];
        i += 3;
    }

    if (i < len)
    {
        uint32_t triple = (uint32_t)input[i] << 16;
        if (i + 1 < len)
            triple |= (uint32_t)input[i + 1] << 8;

        out[j++] = table[(triple >> 18) & 0x3F];
        out[j++] = table[(triple >> 12) & 0x3F];
        out[j++] = (i + 1 < len) ? table[(triple >> 6) & 0x3F] : '=';
        out[j++] = '=';
    }

    out[j] = '\0';
}

static char *ws_trim(char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1]))
        end--;
    *end = '\0';
    return s;
}

static int ws_base64_digit(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

static int ws_base64_decode(const char *input, unsigned char *out, size_t out_cap, size_t *out_len)
{
    size_t len = strlen(input);
    size_t i = 0;
    size_t j = 0;

    if (len == 0 || len % 4 != 0)
        return -1;

    size_t padding = 0;
    if (len >= 2)
    {
        if (input[len - 1] == '=')
            padding++;
        if (input[len - 2] == '=')
            padding++;
    }

    size_t decoded_len = (len / 4) * 3 - padding;
    if (decoded_len > out_cap)
        return -1;

    while (i < len)
    {
        int vals[4];
        for (int k = 0; k < 4; ++k)
        {
            char c = input[i++];
            if (c == '=')
            {
                vals[k] = -2;
            }
            else
            {
                vals[k] = ws_base64_digit(c);
                if (vals[k] < 0)
                    return -1;
            }
        }

        int v0 = vals[0];
        int v1 = vals[1];
        int v2 = vals[2];
        int v3 = vals[3];

        if (v0 < 0 || v1 < 0)
            return -1;

        if (j < decoded_len)
            out[j++] = (unsigned char)((v0 << 2) | (v1 >> 4));
        if (v2 >= 0)
        {
            if (j < decoded_len)
                out[j++] = (unsigned char)(((v1 & 0x0F) << 4) | (v2 >> 2));
            if (v3 >= 0)
            {
                if (j < decoded_len)
                    out[j++] = (unsigned char)(((v2 & 0x03) << 6) | v3);
            }
            else if (v3 != -2)
            {
                return -1;
            }
        }
        else if (v2 != -2)
        {
            return -1;
        }
    }

    *out_len = decoded_len;
    return 0;
}

static int ws_header_has_token(const char *value, const char *token)
{
    size_t tlen = strlen(token);
    const char *ptr = value;

    if (!tlen)
        return 0;

    while (*ptr)
    {
        while (*ptr && (isspace((unsigned char)*ptr) || *ptr == ','))
            ptr++;
        if (!*ptr)
            break;
        const char *start = ptr;
        while (*ptr && *ptr != ',' && !isspace((unsigned char)*ptr))
            ptr++;
        size_t len = (size_t)(ptr - start);
        if (len == tlen)
        {
            size_t match = 0;
            while (match < len)
            {
                unsigned char a = (unsigned char)start[match];
                unsigned char b = (unsigned char)token[match];
                if (tolower(a) != tolower(b))
                    break;
                match++;
            }
            if (match == len)
                return 1;
        }
    }
    return 0;
}

static int ws_validate_utf8(const char *data, size_t len)
{
    size_t i = 0;

    while (i < len)
    {
        unsigned char c = (unsigned char)data[i++];

        if (c <= 0x7F)
            continue;

        if (c >= 0xC2 && c <= 0xDF)
        {
            if (i >= len)
                return -1;
            unsigned char c1 = (unsigned char)data[i++];
            if (c1 < 0x80 || c1 > 0xBF)
                return -1;
            continue;
        }

        if (c == 0xE0)
        {
            if (i + 1 >= len)
                return -1;
            unsigned char c1 = (unsigned char)data[i++];
            unsigned char c2 = (unsigned char)data[i++];
            if (c1 < 0xA0 || c1 > 0xBF || c2 < 0x80 || c2 > 0xBF)
                return -1;
            continue;
        }

        if (c >= 0xE1 && c <= 0xEC)
        {
            if (i + 1 >= len)
                return -1;
            unsigned char c1 = (unsigned char)data[i++];
            unsigned char c2 = (unsigned char)data[i++];
            if (c1 < 0x80 || c1 > 0xBF || c2 < 0x80 || c2 > 0xBF)
                return -1;
            continue;
        }

        if (c == 0xED)
        {
            if (i + 1 >= len)
                return -1;
            unsigned char c1 = (unsigned char)data[i++];
            unsigned char c2 = (unsigned char)data[i++];
            if (c1 < 0x80 || c1 > 0x9F || c2 < 0x80 || c2 > 0xBF)
                return -1;
            continue;
        }

        if (c >= 0xEE && c <= 0xEF)
        {
            if (i + 1 >= len)
                return -1;
            unsigned char c1 = (unsigned char)data[i++];
            unsigned char c2 = (unsigned char)data[i++];
            if (c1 < 0x80 || c1 > 0xBF || c2 < 0x80 || c2 > 0xBF)
                return -1;
            continue;
        }

        if (c == 0xF0)
        {
            if (i + 2 >= len)
                return -1;
            unsigned char c1 = (unsigned char)data[i++];
            unsigned char c2 = (unsigned char)data[i++];
            unsigned char c3 = (unsigned char)data[i++];
            if (c1 < 0x90 || c1 > 0xBF || c2 < 0x80 || c2 > 0xBF || c3 < 0x80 || c3 > 0xBF)
                return -1;
            continue;
        }

        if (c >= 0xF1 && c <= 0xF3)
        {
            if (i + 2 >= len)
                return -1;
            unsigned char c1 = (unsigned char)data[i++];
            unsigned char c2 = (unsigned char)data[i++];
            unsigned char c3 = (unsigned char)data[i++];
            if (c1 < 0x80 || c1 > 0xBF || c2 < 0x80 || c2 > 0xBF || c3 < 0x80 || c3 > 0xBF)
                return -1;
            continue;
        }

        if (c == 0xF4)
        {
            if (i + 2 >= len)
                return -1;
            unsigned char c1 = (unsigned char)data[i++];
            unsigned char c2 = (unsigned char)data[i++];
            unsigned char c3 = (unsigned char)data[i++];
            if (c1 < 0x80 || c1 > 0x8F || c2 < 0x80 || c2 > 0xBF || c3 < 0x80 || c3 > 0xBF)
                return -1;
            continue;
        }

        return -1;
    }

    return 0;
}

static ssize_t ws_header_complete(ws_buffer *buf)
{
    if (buf->len < 4)
        return -1;

    for (size_t i = 0; i + 3 < buf->len; ++i)
    {
        if (buf->data[i] == '\r' && buf->data[i + 1] == '\n' &&
            buf->data[i + 2] == '\r' && buf->data[i + 3] == '\n')
            return (ssize_t)(i + 4);
        if (buf->data[i] == '\n' && buf->data[i + 1] == '\n')
            return (ssize_t)(i + 2);
    }
    return -1;
}

static char *ws_next_line(char **cursor, char *end)
{
    if (*cursor >= end)
        return NULL;

    char *line = *cursor;
    char *p = line;
    while (p < end && *p != '\n')
        p++;
    if (p >= end)
    {
        *cursor = end;
        return NULL;
    }

    char *stop = p;
    if (stop > line && stop[-1] == '\r')
        stop--;
    *stop = '\0';
    *cursor = p + 1;
    return line;
}

static void ws_state_free(ws_state *st)
{
    if (!st)
        return;

    if (st->pending_buf)
        MyFree(st->pending_buf);

    ws_buffer_free(&st->handshake);
    ws_buffer_free(&st->frame_in);
    ws_buffer_free(&st->fragment);
    ws_buffer_free(&st->line_accum);
    ws_buffer_free(&st->pending_lines);
    ws_buffer_free(&st->sendbuf);

    MyFree(st);
}

static ws_state *ws_state_create(aClient *cptr)
{
    ws_state *st = (ws_state *) MyMalloc(sizeof(ws_state));
    if (!st)
        return NULL;

    memset(st, 0, sizeof(*st));
    st->client = cptr;
    ws_buffer_init(&st->handshake);
    ws_buffer_init(&st->frame_in);
    ws_buffer_init(&st->fragment);
    ws_buffer_init(&st->line_accum);
    ws_buffer_init(&st->pending_lines);
    ws_buffer_init(&st->sendbuf);
    return st;
}

static void ws_send_control(aClient *cptr, uint8_t opcode, const char *payload, size_t len)
{
    if (!MyConnect(cptr) || (cptr->flags & FLAGS_DEADSOCKET) || len > 125)
        return;

    unsigned char frame[2 + 8 + 125];
    size_t pos = 0;

    frame[pos++] = 0x80 | (opcode & 0x0F);
    frame[pos++] = (unsigned char)len;
    if (len)
    {
        memcpy(frame + pos, payload, len);
        pos += len;
    }

    sbuf_put(&cptr->sendQ, (char *)frame, pos);
    send_queued(cptr);
}

static void ws_send_close(aClient *cptr, uint16_t code)
{
    unsigned char payload[2];
    payload[0] = (code >> 8) & 0xFF;
    payload[1] = code & 0xFF;
    ws_send_control(cptr, 0x08, (const char *)payload, sizeof(payload));
}

static void ws_send_http_error(aClient *cptr)
{
    static const char response[] = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    sbuf_put(&cptr->sendQ, response, sizeof(response) - 1);
    send_queued(cptr);
}

static void ws_send_version_error(aClient *cptr)
{
    static const char response[] =
        "HTTP/1.1 426 Upgrade Required\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Connection: close\r\n"
        "Content-Length: 0\r\n\r\n";
    sbuf_put(&cptr->sendQ, response, sizeof(response) - 1);
    send_queued(cptr);
}

static int ws_emit_lines(ws_state *st)
{
    size_t pos = 0;
    size_t start = 0;

    while (pos < st->line_accum.len)
    {
        char ch = st->line_accum.data[pos];
        if (ch == '\r' || ch == '\n')
        {
            size_t line_len = pos - start;
            if (line_len > 0)
            {
                if (ws_buffer_append(&st->pending_lines, st->line_accum.data + start, line_len) != 0)
                    return -1;
                if (ws_buffer_append(&st->pending_lines, "\r\n", 2) != 0)
                    return -1;
            }
            while (pos + 1 < st->line_accum.len &&
                   (st->line_accum.data[pos + 1] == '\r' || st->line_accum.data[pos + 1] == '\n'))
                pos++;
            start = pos + 1;
        }
        pos++;
    }

    ws_buffer_consume(&st->line_accum, start);
    return 0;
}

static int ws_flush_pending_lines(ws_state *st)
{
    if (st->pending_lines.len == 0 || st->pending_buf)
        return 0;

    st->pending_buf = (char *) MyMalloc(st->pending_lines.len);
    if (!st->pending_buf)
        return -1;

    memcpy(st->pending_buf, st->pending_lines.data, st->pending_lines.len);
    st->pending_len = st->pending_lines.len;
    st->pending_lines.len = 0;
    if (st->pending_lines.data)
        st->pending_lines.data[0] = '\0';
    st->pending_busy = 0;
    return 0;
}

static int ws_fail_close_code(aClient *cptr, ws_state *st, uint16_t code, const char *reason)
{
    sendto_realops_lev(DEBUG_LEV, "websocket: closing %s (%s, code %u)", cptr->name, reason, (unsigned)code);

    if (st && st->handshake_complete)
        ws_send_close(cptr, code);

    ws_state_free(st);
    cptr->transport_data = NULL;
    cptr->transport_in = NULL;
    cptr->transport_out = NULL;
    cptr->transport_close = NULL;
    ClearWebSocket(cptr);
    exit_client(cptr, cptr, &me, (char *)reason);
    return FLUSH_BUFFER;
}

static int ws_process_frames(aClient *cptr, ws_state *st)
{
    size_t offset = 0;

    while (st->frame_in.len - offset >= 2)
    {
        unsigned char *base = (unsigned char *)st->frame_in.data + offset;
        uint8_t byte1 = base[0];
        uint8_t byte2 = base[1];
        int fin = (byte1 & 0x80) != 0;
        uint8_t opcode = byte1 & 0x0F;
        int masked = (byte2 & 0x80) != 0;
        uint64_t payload_len = (uint64_t)(byte2 & 0x7F);
        size_t header_bytes = 2;
        size_t pos = 2;

        if (byte1 & 0x70)
            return ws_fail_close_code(cptr, st, 1002, "reserved bits set");

        if (!masked)
            return ws_fail_close_code(cptr, st, 1002, "client frame without mask");

        if (payload_len == 126)
        {
            if (st->frame_in.len - offset < pos + 2)
                break;
            payload_len = ((uint64_t)base[pos] << 8) | (uint64_t)base[pos + 1];
            pos += 2;
            header_bytes += 2;
        }
        else if (payload_len == 127)
        {
            if (st->frame_in.len - offset < pos + 8)
                break;
            payload_len = 0;
            for (int i = 0; i < 8; ++i)
                payload_len = (payload_len << 8) | base[pos + i];
            pos += 8;
            header_bytes += 8;
        }

        if (payload_len > SIZE_MAX)
            return ws_fail_close_code(cptr, st, 1009, "payload too large");

        if ((opcode & 0x08) && (!fin || payload_len > 125))
            return ws_fail_close_code(cptr, st, 1002, "invalid control frame");

        if (st->frame_in.len - offset < pos + 4 + (size_t)payload_len)
            break;

        unsigned char mask[4];
        memcpy(mask, base + pos, 4);
        pos += 4;
        header_bytes += 4;

        unsigned char *payload = base + pos;
        size_t payload_sz = (size_t)payload_len;
        for (size_t i = 0; i < payload_sz; ++i)
            payload[i] ^= mask[i % 4];

        if (opcode == 0x08)
        {
            ws_send_close(cptr, 1000);
            ws_state_free(st);
            cptr->transport_data = NULL;
            cptr->transport_in = NULL;
            cptr->transport_out = NULL;
            cptr->transport_close = NULL;
            ClearWebSocket(cptr);
            exit_client(cptr, cptr, &me, "WebSocket closed");
            return FLUSH_BUFFER;
        }
        else if (opcode == 0x09)
        {
            ws_send_control(cptr, 0x0A, (const char *)payload, payload_sz);
        }
        else if (opcode == 0x0A)
        {
            /* ignore pong */
        }
        else if (opcode == 0x01 || (opcode == 0x00 && st->continuation))
        {
            if (opcode == 0x01 && st->continuation)
                ws_buffer_clear(&st->fragment);

            if (ws_buffer_append(&st->fragment, (char *)payload, payload_sz) != 0)
                return ws_fail_close_code(cptr, st, 1011, "oom assembling frame");

            st->continuation = fin ? 0 : 1;
            if (fin)
            {
                if (ws_validate_utf8(st->fragment.data, st->fragment.len) != 0)
                    return ws_fail_close_code(cptr, st, 1007, "invalid utf8 payload");
                if (ws_buffer_append(&st->line_accum, st->fragment.data, st->fragment.len) != 0)
                    return ws_fail_close_code(cptr, st, 1011, "oom buffering text");
                ws_buffer_clear(&st->fragment);
                if (ws_emit_lines(st) != 0)
                    return ws_fail_close_code(cptr, st, 1011, "oom emitting lines");
            }
        }
        else
        {
            return ws_fail_close_code(cptr, st, 1002, "unsupported opcode");
        }

        offset += header_bytes + payload_sz;
    }

    if (offset)
        ws_buffer_consume(&st->frame_in, offset);
    return 0;
}

static int ws_finish_handshake(aClient *cptr, ws_state *st, size_t header_len, int *error_type)
{
    if (error_type)
        *error_type = WS_HANDSHAKE_FAIL;

    if (ws_buffer_reserve(&st->handshake, header_len) != 0)
        return -1;

    char *cursor = st->handshake.data;
    char *end = st->handshake.data + header_len;
    char *line = ws_next_line(&cursor, end);
    if (!line || strncmp(line, "GET ", 4) != 0)
        return -1;

    char key_buf[128];
    key_buf[0] = '\0';
    int has_upgrade = 0;
    int has_connection = 0;
    int version_ok = 0;
    int send_protocol = 0;

    while ((line = ws_next_line(&cursor, end)) != NULL)
    {
        if (*line == '\0')
            break;
        char *colon = strchr(line, ':');
        if (!colon)
            continue;
        *colon = '\0';
        char *name = ws_trim(line);
        char *value = ws_trim(colon + 1);

        if (!strncasecmp(name, "upgrade", 7))
        {
            if (!strncasecmp(value, "websocket", 9))
                has_upgrade = 1;
        }
        else if (!strncasecmp(name, "connection", 10))
        {
            if (ws_header_has_token(value, "upgrade"))
                has_connection = 1;
        }
        else if (!strncasecmp(name, "sec-websocket-key", 17))
        {
            strncpyzt(key_buf, value, sizeof(key_buf));
        }
        else if (!strncasecmp(name, "sec-websocket-version", 21))
        {
            if (!strcmp(value, "13"))
                version_ok = 1;
        }
        else if (!strncasecmp(name, "sec-websocket-protocol", 22))
        {
            if (ws_header_has_token(value, WS_PROTOCOL))
                send_protocol = 1;
        }
    }

    if (!version_ok)
    {
        if (error_type)
            *error_type = WS_HANDSHAKE_UNSUPPORTED_VERSION;
        return -1;
    }

    if (key_buf[0] == '\0' || !has_upgrade || !has_connection)
        return -1;

    unsigned char key_bytes[32];
    size_t key_len = 0;
    if (ws_base64_decode(key_buf, key_bytes, sizeof(key_bytes), &key_len) != 0 || key_len != 16)
    {
        if (error_type)
            *error_type = WS_HANDSHAKE_BAD_KEY;
        return -1;
    }

    char accept_src[sizeof(key_buf) + sizeof(WS_GUID)];
    unsigned char digest[SHA_DIGEST_LENGTH];
    char accept_value[64];

    int accept_src_len = snprintf(accept_src, sizeof(accept_src), "%s%s", key_buf, WS_GUID);
    if (accept_src_len < 0 || (size_t)accept_src_len >= sizeof(accept_src))
        return -1;
    SHA1((unsigned char *)accept_src, strlen(accept_src), digest);
    ws_base64_encode(digest, SHA_DIGEST_LENGTH, accept_value, sizeof(accept_value));

    char response[512];
    int written = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n", accept_value);
    if (written < 0 || written >= (int)sizeof(response))
        return -1;
    if (send_protocol)
    {
        int add = snprintf(response + written, sizeof(response) - written,
                           "Sec-WebSocket-Protocol: %s\r\n", WS_PROTOCOL);
        if (add < 0 || add >= (int)(sizeof(response) - written))
            return -1;
        written += add;
    }
    if (written + 2 >= (int)sizeof(response))
        return -1;
    response[written++] = '\r';
    response[written++] = '\n';

    sbuf_put(&cptr->sendQ, response, written);
    send_queued(cptr);

    size_t remaining = st->handshake.len - header_len;
    if (remaining)
        ws_buffer_append(&st->frame_in, st->handshake.data + header_len, remaining);
    ws_buffer_clear(&st->handshake);

    SetWebSocket(cptr);
    st->handshake_complete = 1;
    if (error_type)
        *error_type = WS_HANDSHAKE_OK;
    return 0;
}

static void ws_transport_close(aClient *cptr)
{
    ws_state *st = (ws_state *) cptr->transport_data;
    if (!st)
        return;

    ws_state_free(st);
    cptr->transport_data = NULL;
    cptr->transport_in = NULL;
    cptr->transport_out = NULL;
    cptr->transport_close = NULL;
    ClearWebSocket(cptr);
}

static void ws_detach_plain(aClient *cptr)
{
    ws_transport_close(cptr);
}

static int ws_transport_out(aClient *to, char *msg, int len, char **out_buf, int *out_len)
{
    ws_state *st = (ws_state *) to->transport_data;
    if (!st || !st->handshake_complete)
        return TRANSPORT_ENCODE_CONTINUE;

    size_t payload = (len < 0) ? 0 : (size_t)len;
    size_t total_payload = payload + 2; /* CRLF */
    size_t header_len = 2;

    if (total_payload > 65535)
        header_len += 8;
    else if (total_payload > 125)
        header_len += 2;

    if (ws_buffer_reserve(&st->sendbuf, header_len + total_payload) != 0)
        return TRANSPORT_ENCODE_DROP;

    unsigned char *base = (unsigned char *)st->sendbuf.data;
    size_t pos = 0;
    base[pos++] = 0x81;
    if (total_payload <= 125)
    {
        base[pos++] = (unsigned char)total_payload;
    }
    else if (total_payload <= 65535)
    {
        base[pos++] = 126;
        base[pos++] = (total_payload >> 8) & 0xFF;
        base[pos++] = total_payload & 0xFF;
    }
    else
    {
        base[pos++] = 127;
        for (int i = 7; i >= 0; --i)
            base[pos++] = (total_payload >> (i * 8)) & 0xFF;
    }

    if (payload)
        memcpy(base + pos, msg, payload);
    pos += payload;
    base[pos++] = '\r';
    base[pos++] = '\n';

    st->sendbuf.len = pos;
    *out_buf = st->sendbuf.data;
    *out_len = (int)st->sendbuf.len;
    return TRANSPORT_ENCODE_REPLACE;
}

static int ws_transport_in(aClient *cptr, char **buf, int *len)
{
    ws_state *st = (ws_state *) cptr->transport_data;
    if (!st)
        return TRANSPORT_FILTER_CONTINUE;

    if (st->pending_buf && st->pending_busy)
    {
        MyFree(st->pending_buf);
        st->pending_buf = NULL;
        st->pending_len = 0;
        st->pending_busy = 0;
    }

    if (!st->handshake_complete)
    {
        if (st->handshake.len == 0 && *len > 0 && (*buf)[0] != 'G')
        {
            ws_detach_plain(cptr);
            return TRANSPORT_FILTER_CONTINUE;
        }
        if (*len > 0 && ws_buffer_append(&st->handshake, *buf, (size_t)(*len)) != 0)
            return ws_fail_close_code(cptr, st, 1011, "oom buffering handshake");
        *len = 0;

        if (st->handshake.len == 0)
            return TRANSPORT_FILTER_BLOCK;

        ssize_t header_len = ws_header_complete(&st->handshake);
        if (header_len < 0)
            return TRANSPORT_FILTER_BLOCK;

        int hs_error = WS_HANDSHAKE_FAIL;
        if (ws_finish_handshake(cptr, st, (size_t)header_len, &hs_error) != 0)
        {
            if (hs_error == WS_HANDSHAKE_UNSUPPORTED_VERSION)
                ws_send_version_error(cptr);
            else
                ws_send_http_error(cptr);
            ws_transport_close(cptr);
            exit_client(cptr, cptr, &me, "WebSocket handshake failed");
            return FLUSH_BUFFER;
        }

        cptr->transport_out = ws_transport_out;
    }
    else if (*len > 0)
    {
        if (ws_buffer_append(&st->frame_in, *buf, (size_t)(*len)) != 0)
            return ws_fail_close_code(cptr, st, 1011, "oom buffering data");
        *len = 0;
    }

    int prc = ws_process_frames(cptr, st);
    if (prc == FLUSH_BUFFER)
        return FLUSH_BUFFER;

    if (ws_flush_pending_lines(st) != 0)
        return ws_fail_close_code(cptr, st, 1011, "oom preparing lines");

    if (st->pending_buf)
    {
        *buf = st->pending_buf;
        *len = (int)st->pending_len;
        st->pending_busy = 1;
        return TRANSPORT_FILTER_CONTINUE;
    }

    return TRANSPORT_FILTER_BLOCK;
}

static int ws_preaccess(aClient *acptr)
{
    if (!MyConnect(acptr) || acptr->transport_data)
        return 0;

    if (!acptr->lstn || !(acptr->lstn->flags & CONF_FLAGS_P_WEBSOCKET))
        return 0;

    ws_state *st = ws_state_create(acptr);
    if (!st)
        return 0;

    acptr->transport_in = ws_transport_in;
    acptr->transport_out = NULL;
    acptr->transport_close = ws_transport_close;
    acptr->transport_data = st;
    return 0;
}

void bircmodule_check(int *version)
{
    *version = MODULE_INTERFACE_VERSION;
}

int bircmodule_init(void *opaque)
{
    preaccess_hook = bircmodule_add_hook(CHOOK_PREACCESS, opaque, ws_preaccess);
    return preaccess_hook ? 0 : -1;
}

void bircmodule_shutdown(void)
{
    if (preaccess_hook)
    {
        bircmodule_del_hook(preaccess_hook);
        preaccess_hook = NULL;
    }
}

void bircmodule_getinfo(char **version, char **description)
{
    static char mod_version[] = "1.0";
    static char mod_desc[] = "WebSocket transport module";
    *version = mod_version;
    *description = mod_desc;
}

int bircmodule_command(aClient *sptr, int parc, char **parv)
{
    return 0;
}

int bircmodule_globalcommand(aClient *cptr, aClient *sptr, int parc, char **parv)
{
    return 0;
}
