// Roman's HTTP service. See http_server.h for the route list.
//
// The connection machinery, the CORS headers and the JSON helpers are carried
// over from the sign firmware (build-pico2-http-firmware) unchanged. What is
// different: the Ed25519 key pair and the device id are no longer compile time
// constants - they are provisioned once through POST /write into the encrypted
// flash store and read back (decrypted) per request.

#include <stdlib.h>
#include <string.h>

#include <lwip/mem.h>
#include <lwip/netif.h>
#include <lwip/tcp.h>
#include <pico/stdlib.h>
#include <stdio.h>

#include "diag.h"
#include "http_server.h"
#include "keystore.h"
#include "led.h"
#include "record.h"
#include "storage.h"
#include "tweetnacl.h"

#include "hardware/watchdog.h"
#include "pico/version.h"

#if DEBUG_AVAILABLE
#include "hardware/clocks.h"
#include "pico/time.h"
#include "pico/unique_id.h"
#endif

// Core 0 stack bounds, provided by the default linker script
// (pico_standard_link/script_include/section_end.incl). Reported at boot and by
// POST /debug.
extern uint32_t __StackTop;
extern uint32_t __StackBottom;

#define HTTP_PORT 80
#define HTTP_MAX_CONN 3
#define HTTP_BUF_SIZE 2048

// POST /write carries two base64 keys and a device id: ~200 bytes in practice.
#define HTTP_WRITE_BODY_LIMIT 1024
#if DEBUG_AVAILABLE
#define HTTP_DEBUG_BODY_LIMIT 256
#endif

static struct tcp_pcb *http_pcb;

typedef struct http_state {
    struct tcp_pcb *pcb;
    char buf[HTTP_BUF_SIZE];
    uint16_t req_len;
    int content_length;
    bool sent;
    bool done;
#if DEBUG_AVAILABLE
    bool reset_after_send; // /debug action=reset: reboot once the reply is ACKed
#endif
} http_state_t;

static http_state_t *http_states[HTTP_MAX_CONN];

// Scratch buffers for the signature reply: the server is single threaded, so
// one request is signed at a time.
static unsigned char sig_sm[2048];
static char sig_b64[128];

static const char BASE64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// ---------------------------------------------------------------------------
// request counters (POST /debug only - compiled out with the endpoint)
// ---------------------------------------------------------------------------

#if DEBUG_AVAILABLE
typedef struct {
    uint32_t requests;   // requests dispatched by http_process_request()
    uint32_t sign_ok;    // POST /sign -> 200
    uint32_t sign_bad;   // POST /sign -> 400/503
    uint32_t write_ok;   // POST /write -> 200 (provisioned)
    uint32_t write_bad;  // POST /write -> 400/403
    uint32_t not_found;  // any request -> 404
    uint32_t too_large;  // any request -> 413
    uint32_t errors;     // 500 responses and tcp_err callbacks
} http_stats_t;

static http_stats_t http_stats;
#define WEB_STAT(field) (http_stats.field++)
#else
#define WEB_STAT(field) ((void)0)
#endif

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

static void base64_encode(const unsigned char *in, int in_len, char *out) {
    int i, j = 0;
    for (i = 0; i < in_len; i += 3) {
        int b = ((int)in[i]) << 16;
        if (i + 1 < in_len) b |= in[i + 1] << 8;
        if (i + 2 < in_len) b |= in[i + 2];
        out[j++] = BASE64[(b >> 18) & 0x3F];
        out[j++] = BASE64[(b >> 12) & 0x3F];
        out[j++] = (i + 1 < in_len) ? BASE64[(b >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < in_len) ? BASE64[b & 0x3F] : '=';
    }
    out[j] = '\0';
}

static int json_get_string(const char *json, const char *key, char *buf, int buf_size) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return -1;
    p++;
    const char *end = strchr(p, '"');
    if (!end) return -1;
    size_t len = (size_t)(end - p);
    if (len >= (size_t)buf_size) len = (size_t)buf_size - 1;
    memcpy(buf, p, len);
    buf[len] = '\0';
    return 0;
}

static const char *storage_state_name(void) {
    switch (keystore_state()) {
        case KEYSTORE_STATE_PROVISIONED:
            return "provisioned";
        case KEYSTORE_STATE_CORRUPT:
            return "corrupt";
        default:
            return "empty";
    }
}

// ---------------------------------------------------------------------------
// connection handling (carried over from the sign firmware)
// ---------------------------------------------------------------------------

static void http_close_conn(struct tcp_pcb *pcb, http_state_t *st) {
    tcp_arg(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_err(pcb, NULL);
    if (st) {
        for (int i = 0; i < HTTP_MAX_CONN; i++) {
            if (http_states[i] == st) {
                http_states[i] = NULL;
                break;
            }
        }
        mem_free(st);
    }
    tcp_arg(pcb, NULL);
    tcp_close(pcb);
}

static err_t http_sent_cb(void *arg, struct tcp_pcb *pcb, uint16_t len) {
    http_state_t *st = (http_state_t *)arg;
    if (!st) return ERR_OK;
    if (st->sent) {
#if DEBUG_AVAILABLE
        // Read the flag before the state is handed back to the pool.
        bool reset_now = st->reset_after_send;
        st->reset_after_send = false;
#endif
        http_close_conn(pcb, st);
#if DEBUG_AVAILABLE
        if (reset_now) {
            printf("http: rebooting\n");
            watchdog_reboot(0, 0, 100);
        }
#endif
    }
    return ERR_OK;
}

static void http_send_response(struct tcp_pcb *pcb, http_state_t *st,
                               int status, const char *body) {
    const char *status_text;
    switch (status) {
        case 200: status_text = "OK"; break;
        case 201: status_text = "Created"; break;
        case 400: status_text = "Bad Request"; break;
        case 403: status_text = "Forbidden"; break;
        case 404: status_text = "Not Found"; break;
        case 405: status_text = "Method Not Allowed"; break;
        case 413: status_text = "Request Entity Too Large"; break;
        case 500: status_text = "Internal Server Error"; break;
        case 503: status_text = "Service Unavailable"; break;
        default:  status_text = "Unknown"; break;
    }

    uint16_t body_len = (uint16_t)strlen(body);
    uint16_t hdr_len = (uint16_t)snprintf(st->buf, HTTP_BUF_SIZE,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "\r\n",
        status, status_text, body_len);

    if (hdr_len + body_len > HTTP_BUF_SIZE) {
        tcp_close(pcb);
        return;
    }

    memcpy(st->buf + hdr_len, body, body_len);
    uint16_t total = hdr_len + body_len;
    st->sent = false;

    err_t err = tcp_write(pcb, st->buf, total, TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK) {
        tcp_close(pcb);
        return;
    }
    tcp_output(pcb);
    st->sent = true;
    st->done = true;
}

static void http_send_404(struct tcp_pcb *pcb, http_state_t *st) {
    WEB_STAT(not_found);
    http_send_response(pcb, st, 404, "{\"error\":\"not found\"}");
}

// ---------------------------------------------------------------------------
// POST /sign
// ---------------------------------------------------------------------------

static void handle_sign_post(struct tcp_pcb *pcb, http_state_t *st, const char *body) {
    led_signal_signing();

    if (body == NULL || *body == '\0') {
        WEB_STAT(sign_bad);
        http_send_response(pcb, st, 400, "{\"error\":\"Empty request body\"}");
        return;
    }

    // The signing key lives in flash; without a provisioned record there is
    // nothing this endpoint can do.
    static uint8_t sk[64];
    if (!keystore_signing_key(sk)) {
        WEB_STAT(sign_bad);
        http_send_response(pcb, st, 503,
                           "{\"error\":\"not provisioned\",\"hint\":\"POST /write first\"}");
        return;
    }

    static char device_id[RECORD_MAX_DEVICE_ID + 1];
    if (!keystore_device_id(device_id, sizeof(device_id))) {
        memset(sk, 0, sizeof(sk));
        WEB_STAT(sign_bad);
        http_send_response(pcb, st, 503, "{\"error\":\"stored record is corrupt\"}");
        return;
    }

    // Static, not on the stack: the signing path is the deepest call chain in
    // the firmware and the server handles one request at a time.
    static char challenge[256], context[128], timestamp[128];
    if (json_get_string(body, "challenge", challenge, sizeof(challenge)) != 0) {
        memset(sk, 0, sizeof(sk));
        WEB_STAT(sign_bad);
        http_send_response(pcb, st, 400, "{\"error\":\"Missing field: challenge\"}");
        return;
    }
    if (json_get_string(body, "context", context, sizeof(context)) != 0) {
        memset(sk, 0, sizeof(sk));
        WEB_STAT(sign_bad);
        http_send_response(pcb, st, 400, "{\"error\":\"Missing field: context\"}");
        return;
    }
    if (json_get_string(body, "timestamp", timestamp, sizeof(timestamp)) != 0) {
        memset(sk, 0, sizeof(sk));
        WEB_STAT(sign_bad);
        http_send_response(pcb, st, 400, "{\"error\":\"Missing field: timestamp\"}");
        return;
    }

    static char sign_body[1024];
    int msg_len = snprintf(sign_body, sizeof(sign_body), "%s:%s:%s:%s",
                           challenge, context, timestamp, device_id);
    if (msg_len < 0 || (size_t)msg_len >= sizeof(sign_body)) {
        memset(sk, 0, sizeof(sk));
        WEB_STAT(sign_bad);
        http_send_response(pcb, st, 400, "{\"error\":\"Message too long\"}");
        return;
    }

    unsigned long long smlen = 0;
    crypto_sign(sig_sm, &smlen, (const unsigned char *)sign_body,
                (unsigned long long)msg_len, sk);
    memset(sk, 0, sizeof(sk)); // the key was only needed for this signature

    base64_encode(sig_sm, 64, sig_b64);

    snprintf(sign_body, sizeof(sign_body),
             "{\"signature\":\"%s\",\"timestamp\":\"%s\",\"device_id\":\"%s\"}",
             sig_b64, timestamp, device_id);
    WEB_STAT(sign_ok);
    http_send_response(pcb, st, 200, sign_body);
}

// ---------------------------------------------------------------------------
// POST /write - one shot provisioning
// ---------------------------------------------------------------------------

static void handle_write_post(struct tcp_pcb *pcb, http_state_t *st, const char *body) {
    // The stored flag is checked before anything else: once the board has been
    // provisioned, every further POST /write is refused with 403 whatever it
    // carries, and flash is never touched again.
    if (keystore_writen()) {
        WEB_STAT(write_bad);
        http_send_response(pcb, st, 403,
                           "{\"error\":\"already provisioned\",\"writen\":true}");
        return;
    }

    if (body == NULL || *body == '\0') {
        WEB_STAT(write_bad);
        http_send_response(pcb, st, 400, "{\"error\":\"Empty request body\"}");
        return;
    }
    if (st->content_length > HTTP_WRITE_BODY_LIMIT) {
        WEB_STAT(too_large);
        http_send_response(pcb, st, 413, "{\"error\":\"request too large\"}");
        return;
    }

    static char pk_b64[64], sk_b64[128], device_id[RECORD_MAX_DEVICE_ID + 1];
    if (json_get_string(body, "pk", pk_b64, sizeof(pk_b64)) != 0) {
        WEB_STAT(write_bad);
        http_send_response(pcb, st, 400, "{\"error\":\"Missing field: pk\"}");
        return;
    }
    if (json_get_string(body, "sk", sk_b64, sizeof(sk_b64)) != 0) {
        WEB_STAT(write_bad);
        http_send_response(pcb, st, 400, "{\"error\":\"Missing field: sk\"}");
        return;
    }
    if (json_get_string(body, "device_id", device_id, sizeof(device_id)) != 0) {
        WEB_STAT(write_bad);
        http_send_response(pcb, st, 400, "{\"error\":\"Missing field: device_id\"}");
        return;
    }

    diag_stage(DIAG_STAGE_RECEIVED);
    printf("http: /write received (%u byte body)\n", (unsigned)st->content_length);
    // keystore_provision() checks the stored flag before it parses anything, so
    // an already provisioned board never reaches the flash.
    switch (keystore_provision(pk_b64, sk_b64, device_id)) {
        case KEYSTORE_OK:
            WEB_STAT(write_ok);
            printf("http: provisioned device_id=%s\n", device_id);
            http_send_response(pcb, st, 200, "{\"status\":\"ok\",\"writen\":true}");
            break;
        case KEYSTORE_ERR_ALREADY:
            WEB_STAT(write_bad);
            http_send_response(pcb, st, 403,
                               "{\"error\":\"already provisioned\",\"writen\":true}");
            break;
        case KEYSTORE_ERR_MISMATCH:
            WEB_STAT(write_bad);
            http_send_response(pcb, st, 400, "{\"error\":\"pk does not match sk\"}");
            break;
        case KEYSTORE_ERR_FLASH:
            WEB_STAT(errors);
            http_send_response(pcb, st, 500, "{\"error\":\"flash write failed\"}");
            break;
        case KEYSTORE_ERR_ARG:
        default:
            WEB_STAT(write_bad);
            http_send_response(pcb, st, 400,
                               "{\"error\":\"invalid pk/sk/device_id\"}");
            break;
    }
}

// ---------------------------------------------------------------------------
// GET /info
// ---------------------------------------------------------------------------

static void handle_info(struct tcp_pcb *pcb, http_state_t *st) {
    static char device_id[RECORD_MAX_DEVICE_ID + 1];
    static char id_json[RECORD_MAX_DEVICE_ID + 8];
    if (keystore_device_id(device_id, sizeof(device_id))) {
        snprintf(id_json, sizeof(id_json), "\"%s\"", device_id);
    } else {
        snprintf(id_json, sizeof(id_json), "null");
    }

    static char info_buf[320];
    snprintf(info_buf, sizeof(info_buf),
             "{\"device\":\"pico2\",\"firmware\":\"roman\",\"version\":\"0.1\","
             "\"engine\":\"C/tweetnacl\",\"id\":%s,\"storage\":\"%s\"}",
             id_json, storage_state_name());
    http_send_response(pcb, st, 200, info_buf);
}

#if DEBUG_AVAILABLE
// ---------------------------------------------------------------------------
// POST /debug
// ---------------------------------------------------------------------------

// Must match STORAGE_FLASH_OFFSET in storage.c.
#define DEBUG_STORAGE_FLASH_OFFSET (1024u * 1024u)

static char debug_json[1280];
static uint8_t debug_read_buf[STORAGE_MAX_PAYLOAD];

// Decrypts the whole stored payload (Poly1305 verified) to report whether the
// store is empty, corrupt or healthy.
static const char *debug_selftest(size_t *plaintext_len, bool *available) {
    *plaintext_len = 0;
    *available = storage_available();
    if (!*available) {
        return "empty";
    }
    size_t n = storage_read(debug_read_buf, sizeof(debug_read_buf));
    if (n == 0) {
        return "corrupt";
    }
    *plaintext_len = n;
    return "ok";
}

static void debug_snapshot(struct tcp_pcb *pcb, http_state_t *st) {
    size_t plaintext_len = 0;
    bool available = false;
    const char *selftest = debug_selftest(&plaintext_len, &available);

    unsigned conns = 0;
    for (int i = 0; i < HTTP_MAX_CONN; ++i) {
        if (http_states[i] != NULL) {
            ++conns;
        }
    }

    static char unique_id[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];
    pico_get_unique_board_id_string(unique_id, sizeof(unique_id));

    // netif_default is only NULL before usb_network_init() has run.
    char mac[18] = "00:00:00:00:00:00";
    const char *ip = "0.0.0.0";
    bool link_up = false;
    if (netif_default != NULL) {
        static const char hex[] = "0123456789ABCDEF";
        for (int i = 0; i < 6; ++i) {
            mac[i * 3] = hex[(netif_default->hwaddr[i] >> 4) & 0xF];
            mac[i * 3 + 1] = hex[netif_default->hwaddr[i] & 0xF];
            mac[i * 3 + 2] = (i < 5) ? ':' : '\0';
        }
        ip = ip4addr_ntoa(&netif_default->ip_addr);
        link_up = netif_is_link_up(netif_default);
    }

    // Roman specifics: the stored flag, the id and both public keys.
    static char ed_b64[64], x_b64[64];
    static uint8_t pk[32];
    ed_b64[0] = '\0';
    x_b64[0] = '\0';
    if (keystore_public_key(pk)) {
        base64_encode(pk, 32, ed_b64);
    }
    if (storage_x25519_pk(pk)) {
        base64_encode(pk, 32, x_b64);
    }
    static char device_id[RECORD_MAX_DEVICE_ID + 1];
    static char id_json[RECORD_MAX_DEVICE_ID + 8];
    if (keystore_device_id(device_id, sizeof(device_id))) {
        snprintf(id_json, sizeof(id_json), "\"%s\"", device_id);
    } else {
        snprintf(id_json, sizeof(id_json), "null");
    }

    int n = snprintf(debug_json, sizeof(debug_json),
                     "{\"status\":\"ok\",\"debug\":{"
                     "\"uptime_ms\":%u,\"sdk\":\"%s\",\"cpu_mhz\":%u,\"unique_id\":\"%s\","
                     "\"reset_by_watchdog\":%s,"
                     "\"stack\":{\"used_now\":%u,\"total\":%u},"
                     "\"net\":{\"ip\":\"%s\",\"mac\":\"%s\",\"link_up\":%s},"
                     "\"web\":{\"conns\":%u,\"conns_max\":%d,\"requests\":%u,\"sign_ok\":%u,"
                     "\"sign_bad\":%u,\"write_ok\":%u,\"write_bad\":%u,\"not_found\":%u,"
                     "\"too_large\":%u,\"errors\":%u},"
                     "\"storage\":{\"writen\":%s,\"available\":%s,\"selftest\":\"%s\","
                     "\"plaintext_len\":%u,\"max_payload\":%d,\"flash_offset\":%u},"
                     "\"roman\":{\"device_id\":%s,\"ed25519_pk\":\"%s\",\"x25519_pk\":\"%s\","
                     "\"last_stage\":\"%s\",\"reset_by_watchdog\":%s}"
                     "}}",
                     (unsigned)to_ms_since_boot(get_absolute_time()),
                     PICO_SDK_VERSION_STRING,
                     (unsigned)(clock_get_hz(clk_sys) / 1000000u),
                     unique_id,
                     watchdog_caused_reboot() ? "true" : "false",
                     (unsigned)((uintptr_t)&__StackTop - (uintptr_t)__builtin_frame_address(0)),
                     (unsigned)((uintptr_t)&__StackTop - (uintptr_t)&__StackBottom),
                     ip, mac, link_up ? "true" : "false",
                     conns, HTTP_MAX_CONN,
                     (unsigned)http_stats.requests, (unsigned)http_stats.sign_ok,
                     (unsigned)http_stats.sign_bad, (unsigned)http_stats.write_ok,
                     (unsigned)http_stats.write_bad, (unsigned)http_stats.not_found,
                     (unsigned)http_stats.too_large, (unsigned)http_stats.errors,
                     storage_writen() ? "true" : "false",
                     available ? "true" : "false", selftest, (unsigned)plaintext_len,
                     STORAGE_MAX_PAYLOAD, DEBUG_STORAGE_FLASH_OFFSET,
                     id_json, ed_b64, x_b64,
                     diag_stage_name(diag_boot_stage()),
                     watchdog_caused_reboot() ? "true" : "false");

    if (n < 0 || (size_t)n >= sizeof(debug_json)) {
        WEB_STAT(errors);
        http_send_response(pcb, st, 500,
                           "{\"status\":\"error\",\"error\":\"debug overflow\"}");
        return;
    }
    http_send_response(pcb, st, 200, debug_json);
}

static void handle_debug(struct tcp_pcb *pcb, http_state_t *st, const char *body) {
    if (st->content_length > HTTP_DEBUG_BODY_LIMIT) {
        WEB_STAT(too_large);
        http_send_response(pcb, st, 413, "{\"status\":\"error\",\"error\":\"request too large\"}");
        return;
    }

    // A body without a usable action is a snapshot: a typo must never trigger
    // something destructive.
    char action[16];
    if (body == NULL || *body == '\0' ||
        json_get_string(body, "action", action, sizeof(action)) != 0 ||
        action[0] == '\0') {
        debug_snapshot(pcb, st);
        return;
    }
    if (strcmp(action, "snapshot") == 0) {
        debug_snapshot(pcb, st);
        return;
    }
    if (strcmp(action, "clear") == 0) {
        printf("http: /debug clear\n");
        if (!storage_clear()) {
            WEB_STAT(errors);
            http_send_response(pcb, st, 500,
                               "{\"status\":\"error\",\"error\":\"flash erase failed\"}");
            return;
        }
        keystore_invalidate();
        http_send_response(pcb, st, 200,
                           "{\"status\":\"ok\",\"action\":\"clear\",\"writen\":false}");
        return;
    }
    if (strcmp(action, "reset") == 0) {
        // Armed here, fired from http_sent_cb() once the reply is acknowledged.
        st->reset_after_send = true;
        http_send_response(pcb, st, 200,
                           "{\"status\":\"ok\",\"action\":\"reset\",\"note\":\"rebooting\"}");
        return;
    }
    http_send_response(pcb, st, 400,
                       "{\"status\":\"error\",\"error\":\"unknown action\"}");
}
#endif // DEBUG_AVAILABLE

// ---------------------------------------------------------------------------
// routing
// ---------------------------------------------------------------------------

static void http_process_request(struct tcp_pcb *pcb, http_state_t *st) {
    // Static, not on the stack: every byte of margin counts on the deep crypto
    // paths below (see the stack note in README.md).
    static char method[16], path[128];
    method[0] = '\0';
    path[0] = '\0';

    char *sp1 = strchr(st->buf, ' ');
    if (!sp1) {
        http_send_404(pcb, st);
        return;
    }
    uint16_t mlen = (uint16_t)(sp1 - st->buf);
    if (mlen >= sizeof(method)) mlen = sizeof(method) - 1;
    memcpy(method, st->buf, mlen);

    sp1++;
    char *sp2 = strchr(sp1, ' ');
    if (!sp2) {
        http_send_404(pcb, st);
        return;
    }
    uint16_t plen = (uint16_t)(sp2 - sp1);
    if (plen >= sizeof(path)) plen = sizeof(path) - 1;
    memcpy(path, sp1, plen);

    char *sep = strstr(st->buf, "\r\n\r\n");
    char *body = sep ? sep + 4 : NULL;

#if DEBUG_AVAILABLE
    WEB_STAT(requests);
#endif

    if (strcmp(method, "OPTIONS") == 0) {
        http_send_response(pcb, st, 200, "");
        return;
    }

    if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "/") == 0) {
            http_send_response(pcb, st, 200,
                "{\"device\":\"pico2\",\"firmware\":\"roman\",\"ip\":\"192.168.7.1\","
                "\"status\":\"running\",\"endpoints\":"
                "[\"/health\",\"/sign\",\"/info\",\"/write\",\"/debug\"]}");
        } else if (strcmp(path, "/health") == 0) {
            http_send_response(pcb, st, 200, "{\"status\":\"ok\"}");
        } else if (strcmp(path, "/info") == 0) {
            handle_info(pcb, st);
        } else if (strcmp(path, "/sign") == 0) {
            http_send_response(pcb, st, 200,
                "{\"endpoint\":\"/sign\",\"method\":\"POST\","
                "\"fields\":[\"challenge\",\"context\",\"timestamp\"]}");
        } else {
            http_send_404(pcb, st);
        }
        return;
    }

    if (strcmp(method, "POST") == 0) {
        if (strcmp(path, "/sign") == 0) {
            handle_sign_post(pcb, st, body);
        } else if (strcmp(path, "/write") == 0) {
            handle_write_post(pcb, st, body);
#if DEBUG_AVAILABLE
        } else if (strcmp(path, "/debug") == 0) {
            handle_debug(pcb, st, body);
#endif
        } else {
            http_send_404(pcb, st);
        }
        return;
    }

    http_send_404(pcb, st);
}

// ---------------------------------------------------------------------------
// lwIP callbacks (carried over from the sign firmware)
// ---------------------------------------------------------------------------

static err_t http_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    http_state_t *st = (http_state_t *)arg;
    if (!st) return ERR_VAL;

    if (!p) {
        http_close_conn(pcb, st);
        return ERR_OK;
    }

    if (st->done) {
        pbuf_free(p);
        return ERR_OK;
    }

    uint16_t data_len = p->tot_len;

    if (err != ERR_OK) {
        pbuf_free(p);
        return err;
    }

    if (st->req_len + data_len >= HTTP_BUF_SIZE) {
        pbuf_free(p);
        tcp_recved(pcb, data_len);
        WEB_STAT(too_large);
        http_send_response(pcb, st, 413, "{\"error\":\"Request too large\"}");
        return ERR_OK;
    }

    pbuf_copy_partial(p, st->buf + st->req_len, data_len, 0);
    st->req_len += data_len;
    st->buf[st->req_len] = '\0';

    pbuf_free(p);

    if (st->content_length < 0) {
        char *cl = strstr(st->buf, "Content-Length:");
        if (!cl) cl = strstr(st->buf, "content-length:");
        if (cl) {
            char *val = strchr(cl, ':');
            if (val) st->content_length = atoi(val + 1);
        } else {
            st->content_length = 0;
        }
    }

    char *sep = strstr(st->buf, "\r\n\r\n");
    if (!sep) {
        tcp_recved(pcb, data_len);
        return ERR_OK;
    }

    int header_end = (int)(sep - st->buf) + 4;
    int body_received = (int)st->req_len - header_end;

    if (st->content_length > 0 && body_received < st->content_length) {
        tcp_recved(pcb, data_len);
        return ERR_OK;
    }

    tcp_recved(pcb, data_len);
    http_process_request(pcb, st);
    return ERR_OK;
}

static void http_err_cb(void *arg, err_t err) {
    (void)err;
    WEB_STAT(errors);
    led_signal_error();
    http_state_t *st = (http_state_t *)arg;
    if (st) {
        for (int i = 0; i < HTTP_MAX_CONN; i++) {
            if (http_states[i] == st) {
                http_states[i] = NULL;
                break;
            }
        }
        mem_free(st);
    }
}

static err_t http_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err) {
    (void)arg;
    if (err != ERR_OK || newpcb == NULL) {
        return ERR_VAL;
    }

    http_state_t *st = (http_state_t *)mem_malloc(sizeof(http_state_t));
    if (!st) {
        tcp_close(newpcb);
        return ERR_MEM;
    }
    memset(st, 0, sizeof(http_state_t));
    st->pcb = newpcb;
    st->content_length = -1;

    int slot = -1;
    for (int i = 0; i < HTTP_MAX_CONN; i++) {
        if (http_states[i] == NULL) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        mem_free(st);
        tcp_close(newpcb);
        return ERR_MEM;
    }
    http_states[slot] = st;

    tcp_arg(newpcb, st);
    tcp_sent(newpcb, http_sent_cb);
    tcp_recv(newpcb, http_recv_cb);
    tcp_err(newpcb, http_err_cb);
    tcp_nagle_disable(newpcb);

    led_signal_activity();
    return ERR_OK;
}

// ---------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------

bool http_server_init(void) {
    const char *state;
    switch (keystore_state()) {
        case KEYSTORE_STATE_PROVISIONED: state = "provisioned"; break;
        case KEYSTORE_STATE_CORRUPT:     state = "corrupt"; break;
        default:                          state = "empty"; break;
    }
    printf("http: storage %s, file an Ed25519 key pair with POST /write\n", state);
    if (storage_writen()) {
        printf("http: writen=1, POST /write will answer 403\n");
    }
    // Boot diagnostics: the two numbers that decide whether the deep crypto
    // paths have room, and which entropy path is in use.
    printf("http: stack %u bytes, sdk %s, reset_by_watchdog=%d\n",
           (unsigned)((uintptr_t)&__StackTop - (uintptr_t)&__StackBottom),
           PICO_SDK_VERSION_STRING,
           watchdog_caused_reboot() ? 1 : 0);
    printf("http: entropy source: %s\n",
           storage_trng_probe() ? "hardware TRNG" : "TRNG-seeded fallback");

    http_pcb = tcp_new();
    if (!http_pcb) {
        printf("http: failed to create pcb\n");
        return false;
    }

    if (tcp_bind(http_pcb, IP_ADDR_ANY, HTTP_PORT) != ERR_OK) {
        printf("http: failed to bind port %d\n", HTTP_PORT);
        tcp_close(http_pcb);
        http_pcb = NULL;
        return false;
    }

    http_pcb = tcp_listen(http_pcb);
    if (!http_pcb) {
        printf("http: failed to listen\n");
        return false;
    }

    tcp_accept(http_pcb, http_accept_cb);
    printf("http: listening on port %d\n", HTTP_PORT);
    return true;
}

void http_server_deinit(void) {
    if (http_pcb) {
        tcp_close(http_pcb);
        http_pcb = NULL;
    }
    for (int i = 0; i < HTTP_MAX_CONN; i++) {
        if (http_states[i]) {
            http_close_conn(http_states[i]->pcb, http_states[i]);
        }
    }
}
