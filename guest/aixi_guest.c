#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#define NYX_LITE 0x6574696c2d78796eULL
#define HYPERCALL_EXECDONE 0x656e6f6463657865ULL
#define HYPERCALL_SNAPSHOT 0x746f687370616e73ULL
#define HYPERCALL_SHAREMEM 0x6d656d6572616873ULL
#define HYPERCALL_DBGPRINT 0x746e697270676264ULL

#define SHARED_SIZE 4096
#define ACTION_LEN_OFFSET 0
#define RESP_LEN_OFFSET 8
#define PAYLOAD_OFFSET 16
#define MAX_PAYLOAD (SHARED_SIZE - PAYLOAD_OFFSET)

static uint8_t shared[SHARED_SIZE];

static inline void hypercall(uint64_t hypercall_num,
                             uint64_t arg1,
                             uint64_t arg2,
                             uint64_t arg3,
                             uint64_t arg4) {
    register uint64_t rax asm("rax") = NYX_LITE;
    register uint64_t r8 asm("r8") = hypercall_num;
    register uint64_t r9 asm("r9") = arg1;
    register uint64_t r10 asm("r10") = arg2;
    register uint64_t r11 asm("r11") = arg3;
    register uint64_t r12 asm("r12") = arg4;
    __asm__ __volatile__(
        "int $3\n"
        : "+a"(rax)
        : "r"(r8), "r"(r9), "r"(r10), "r"(r11), "r"(r12)
        : "memory");
}

static inline void register_shared(const char *name, void *buf, size_t len) {
    hypercall(HYPERCALL_SHAREMEM, (uint64_t)name, (uint64_t)buf, (uint64_t)len, 0);
}

static inline void request_snapshot(void) {
    hypercall(HYPERCALL_SNAPSHOT, 0, 0, 0, 0);
}

static inline void debug_print(const char *msg) {
    hypercall(HYPERCALL_DBGPRINT, (uint64_t)msg, 0, 0, 0);
}

static inline void signal_step(uint64_t obs, int64_t rew) {
    // Use a non-reserved hypercall code so the host receives ExitReason::Hypercall.
    const uint64_t CODE = 0x414958495f535445ULL; // "AIXI_STE"
    hypercall(CODE, obs, (uint64_t)rew, 0, 0);
}

static inline uint64_t read_u64_le(const uint8_t *p) {
    return ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline void write_u64_le(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
    p[4] = (uint8_t)((v >> 32) & 0xff);
    p[5] = (uint8_t)((v >> 40) & 0xff);
    p[6] = (uint8_t)((v >> 48) & 0xff);
    p[7] = (uint8_t)((v >> 56) & 0xff);
}

static uint64_t fnv1a64(const uint8_t *data, size_t len) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static void write_response(const uint8_t *buf, size_t len) {
    if (len > MAX_PAYLOAD) {
        len = MAX_PAYLOAD;
    }
    write_u64_le(shared + RESP_LEN_OFFSET, (uint64_t)len);
    if (len > 0) {
        memcpy(shared + PAYLOAD_OFFSET, buf, len);
    }
}

static int starts_with(const uint8_t *buf, size_t len, const char *s) {
    size_t sl = strlen(s);
    if (len < sl) {
        return 0;
    }
    return memcmp(buf, s, sl) == 0;
}

int main(void) {
    // Register shared memory region.
    memset(shared, 0, sizeof(shared));
    debug_print("aixi_guest: booting");
    register_shared("shared", shared, sizeof(shared));

    // Ensure snapshot starts with empty shared buffer.
    write_u64_le(shared + ACTION_LEN_OFFSET, 0);
    write_u64_le(shared + RESP_LEN_OFFSET, 0);
    request_snapshot();
    debug_print("aixi_guest: snapshot requested");

    for (;;) {
        // Busy-wait for an action to arrive.
        uint64_t len = read_u64_le(shared + ACTION_LEN_OFFSET);
        if (len == 0 || len > MAX_PAYLOAD) {
            // Sleep briefly to avoid burning CPU if no action yet.
            usleep(1000);
            continue;
        }

        const uint8_t *payload = shared + PAYLOAD_OFFSET;
        size_t payload_len = (size_t)len;

        uint8_t response[MAX_PAYLOAD];
        size_t resp_len = 0;
        int64_t reward = 0;

        if (starts_with(payload, payload_len, "PING")) {
            const char *msg = "PING";
            resp_len = strlen(msg);
            memcpy(response, msg, resp_len);
            reward = 1;
        } else if (starts_with(payload, payload_len, "STATUS")) {
            const char *msg = "STATUS:OK";
            resp_len = strlen(msg);
            memcpy(response, msg, resp_len);
            reward = 2;
        } else {
            const char *prefix = "ECHO:";
            size_t prefix_len = strlen(prefix);
            resp_len = prefix_len;
            memcpy(response, prefix, prefix_len);
            size_t copy_len = payload_len;
            if (resp_len + copy_len > MAX_PAYLOAD) {
                copy_len = MAX_PAYLOAD - resp_len;
            }
            memcpy(response + resp_len, payload, copy_len);
            resp_len += copy_len;
            reward = (int64_t)(payload_len & 0x0f);
        }

        write_response(response, resp_len);

        uint64_t obs = fnv1a64(response, resp_len);
        // Mark action consumed before notifying the host.
        write_u64_le(shared + ACTION_LEN_OFFSET, 0);
        signal_step(obs, reward);
    }

    return 0;
}
