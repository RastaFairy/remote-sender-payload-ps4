/*
 * ps4-pkgsender-payload v7.21
 * Compilado con ps4-payload-sdk (gcc + libPS4)
 *
 * CAMBIOS v7.21
 * - Recupera compatibilidad de API (/api/status, /api/debug, /api/get_task_progress).
 * - Endurece registro BGFT con más variantes de parámetros para evitar 0x80990002.
 * - Mantiene soporte URL larga + normalización RFC3986 + JSON unicode/UTF-8.
 */

#include <ps4.h>

#define URL_MAX  32768
#define BUF_MAX  65536

/* ── dynlib syscalls ────────────────────────────────────────────────────── */
struct ps4_module_segment {
    uint64_t addr;
    uint32_t size;
    uint32_t flags;
};
struct ps4_module_info_ex {
    size_t   st_size;
    char     name[256];
    int      id;
    uint32_t tls_index;
    uint64_t tls_init_addr;
    uint32_t tls_init_size;
    uint32_t tls_size;
    uint32_t tls_offset;
    uint32_t tls_align;
    uint64_t init_proc_addr;
    uint64_t fini_proc_addr;
    uint64_t reserved1;
    uint64_t reserved2;
    uint64_t eh_frame_hdr_addr;
    uint64_t eh_frame_addr;
    uint32_t eh_frame_hdr_size;
    uint32_t eh_frame_size;
    struct ps4_module_segment segments[4];
    uint32_t segment_count;
    uint32_t ref_count;
};

static int ps4_dynlib_load_prx(const char *path, int flags, int *handle, int zero2)
{
    register long        rax __asm__("rax") = 594;
    register const char *rdi __asm__("rdi") = path;
    register long        rsi __asm__("rsi") = flags;
    register int        *rdx __asm__("rdx") = handle;
    register long        r10 __asm__("r10") = zero2;
    long ret;
    __asm__ volatile("syscall"
        : "=a"(ret) : "r"(rax),"r"(rdi),"r"(rsi),"r"(rdx),"r"(r10)
        : "rcx","r11","memory");
    return (int)ret;
}

/* ── BGFT ───────────────────────────────────────────────────────────────── */
typedef struct {
    size_t size;
    void  *mem;
} bgft_init_params_t;

typedef struct {
    uint32_t    entitlement_type;
    uint32_t    user_id;
    const char *id;
    const char *content_url;
    const char *content_name;
    const char *icon_path;
    const char *sku_id;
    const char *playgo_scenario_id;
    const char *release_date;
    const char *package_type;
    const char *package_sub_type;
    uint64_t    package_size;
    uint32_t    option;
} bgft_task_param_t;

#define BGFT_TASK_OPT_NONE        0x00000000
#define BGFT_TASK_OPT_DELETE_PKG  0x00000001
#define BGFT_TASK_OPT_INVISIBLE   0x00000002
#define BGFT_TASK_OPT_REMOTE      0x00000010
#define BGFT_TASK_OPT_DISABLE_CDN 0x00010000

static int (*fn_bgft_init)(bgft_init_params_t *p)                    = NULL;
static int (*fn_bgft_reg) (const bgft_task_param_t *p, int *task_id) = NULL;
static int (*fn_bgft_start)(int task_id)                              = NULL;

static int bgft_loaded  = 0;
static int bgft_inited  = 0;
static int last_task    = -1;
static int last_bgft_rr = 0;
static int last_user_id = 0x10000000;
static int last_reg_attempts = 0;
static int g_jb_result  = 0;
static int g_shutdown   = 0;
static int g_srv_fd     = -1;
static char g_bgft_path[256] = {0};
static char g_fw_string[64] = "unknown";
static uint32_t g_fw_raw = 0;
static const char *g_log_path = "/data/pkgsender.log";

static void log_line(const char *line) {
    /* Compatibilidad SDK:
     * - En SDK oficial moderno existe vsnprintf, pero en entornos homebrew/
     *   ps4-payload-sdk puede faltar símbolo en link dependiendo de libc.
     * - Evitamos varargs aquí para compilar de forma consistente en ambos. */
    FILE *f = fopen(g_log_path, "a");
    if (!f) return;
    fprintf(f, "%s\n", line ? line : "");
    fclose(f);
}

static void detect_firmware(void) {
    SceFwInfo info;
    memset(&info, 0, sizeof(info));
    if (!sceKernelGetSystemSwVersion) return;
    if (sceKernelGetSystemSwVersion(&info) < 0) return;
    g_fw_raw = info.version;
    if (info.version_string[0]) {
        strncpy(g_fw_string, info.version_string, sizeof(g_fw_string) - 1);
        g_fw_string[sizeof(g_fw_string) - 1] = '\0';
    }
}

/* ── HTTP helpers ──────────────────────────────────────────────────────── */
static const char CORS[] =
    "Access-Control-Allow-Origin: *\r\n"
    "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
    "Access-Control-Allow-Headers: Content-Type\r\n";

static void notify(const char *msg) { printf_notification("%s", msg); }

static void http_send(int fd, int code, const char *body) {
    const char *st =
        code == 200 ? "OK" :
        code == 204 ? "No Content" :
        code == 400 ? "Bad Request" :
        code == 404 ? "Not Found" : "Internal Server Error";
    char hdr[512];
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Content-Length: %d\r\n"
        "%s"
        "Connection: close\r\n\r\n",
        code, st, (int)strlen(body), CORS);
    sceNetSend(fd, hdr, hlen, 0);
    if (body[0]) sceNetSend(fd, body, strlen(body), 0);
}

static int parse_int(const char *s) {
    while (*s == ' ' || *s == '\t') s++;
    int r = 0;
    while (*s >= '0' && *s <= '9') r = r * 10 + (*s++ - '0');
    return r;
}

static int recv_http(int fd, char *buf, int bufsz) {
    int total = 0;
    buf[0] = '\0';
    while (total < bufsz - 1) {
        int n = sceNetRecv(fd, buf + total, bufsz - 1 - total, 0);
        if (n <= 0) break;
        total += n;
        buf[total] = '\0';
        char *hdr_end = strstr(buf, "\r\n\r\n");
        if (!hdr_end) continue;
        int body_start = (int)(hdr_end - buf) + 4;
        char *cl = strstr(buf, "\r\nContent-Length:");
        if (!cl) cl = strstr(buf, "\r\ncontent-length:");
        if (!cl) break;
        int clen = parse_int(cl + 17);
        if (clen <= 0) break;
        int body_recv = total - body_start;
        while (body_recv < clen && total < bufsz - 1) {
            int want = clen - body_recv;
            int room = bufsz - 1 - total;
            if (want > room) want = room;
            n = sceNetRecv(fd, buf + total, want, 0);
            if (n <= 0) break;
            total += n;
            body_recv += n;
        }
        buf[total] = '\0';
        break;
    }
    return total;
}

/* ── JSON helpers ──────────────────────────────────────────────────────── */
static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int hex_byte(char hi, char lo) {
    int h = hex_nibble(hi);
    int l = hex_nibble(lo);
    if (h < 0 || l < 0) return -1;
    return (h << 4) | l;
}

static int utf8_write(int cp, char *out, int i, int sz) {
    if (cp < 0 || i >= sz - 1) return i;
    if (cp < 0x80) {
        if (i < sz - 1) out[i++] = (char)cp;
    } else if (cp < 0x800) {
        if (i < sz - 2) {
            out[i++] = (char)(0xC0 | (cp >> 6));
            out[i++] = (char)(0x80 | (cp & 0x3F));
        }
    } else if (cp < 0x10000) {
        if (i < sz - 3) {
            out[i++] = (char)(0xE0 | (cp >> 12));
            out[i++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            out[i++] = (char)(0x80 | (cp & 0x3F));
        }
    } else if (cp < 0x110000) {
        if (i < sz - 4) {
            out[i++] = (char)(0xF0 | (cp >> 18));
            out[i++] = (char)(0x80 | ((cp >> 12) & 0x3F));
            out[i++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            out[i++] = (char)(0x80 | (cp & 0x3F));
        }
    }
    return i;
}

static int json_hex4(const char *p) {
    int a = hex_nibble(p[0]), b = hex_nibble(p[1]), c = hex_nibble(p[2]), d = hex_nibble(p[3]);
    if (a < 0 || b < 0 || c < 0 || d < 0) return -1;
    return (a << 12) | (b << 8) | (c << 4) | d;
}

static int json_str(const char *js, const char *key, char *out, int sz) {
    if (!js || !key || !out || sz <= 0) return -1;
    out[0] = '\0';
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    char *p = strstr((char *)js, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    if (*p != '"') return -1;
    p++;
    int i = 0;
    while (*p && i < sz - 1) {
        if (*p == '"') break;
        if (*p == '\\' && *(p + 1)) {
            p++;
            switch (*p) {
            case '"':  out[i++] = '"';  break;
            case '\\': out[i++] = '\\'; break;
            case '/':  out[i++] = '/';  break;
            case 'n':  out[i++] = '\n'; break;
            case 'r':  out[i++] = '\r'; break;
            case 't':  out[i++] = '\t'; break;
            case 'u': {
                if (p[1] && p[2] && p[3] && p[4]) {
                    int cp = json_hex4(p + 1);
                    if (cp >= 0) i = utf8_write(cp, out, i, sz);
                    p += 4;
                }
                break;
            }
            default: out[i++] = *p; break;
            }
        } else {
            out[i++] = *p;
        }
        p++;
    }
    out[i] = '\0';
    return i;
}

static int json_arr_first(const char *js, const char *key, char *out, int sz) {
    if (!js || !key || !out || sz <= 0) return -1;
    out[0] = '\0';
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    char *p = strstr((char *)js, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p != '[') return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '"') return -1;
    p++;
    int i = 0;
    while (*p && i < sz - 1) {
        if (*p == '"') break;
        if (*p == '\\' && *(p + 1)) {
            p++;
            if (*p == 'u' && p[1] && p[2] && p[3] && p[4]) {
                int cp = json_hex4(p + 1);
                if (cp >= 0) i = utf8_write(cp, out, i, sz);
                p += 4;
            } else if (*p == '/') out[i++] = '/';
            else if (*p == '"') out[i++] = '"';
            else if (*p == '\\') out[i++] = '\\';
            else out[i++] = *p;
            p++;
            continue;
        }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return i;
}

static int json_int(const char *js, const char *key, int def) {
    if (!js || !key) return def;
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    char *p = strstr((char *)js, needle);
    if (!p) return def;
    p += strlen(needle);
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    if (*p < '0' || *p > '9') return def;
    return parse_int(p);
}

/* ── URL helpers ───────────────────────────────────────────────────────── */
static void url_decode(const char *src, char *dst, int dsz) {
    int o = 0;
    while (*src && o < dsz - 1) {
        if (*src == '%' && src[1] && src[2]) {
            int v = hex_byte(src[1], src[2]);
            if (v >= 0) { dst[o++] = (char)v; src += 3; continue; }
        } else if (*src == '+') { dst[o++] = ' '; src++; continue; }
        dst[o++] = *src++;
    }
    dst[o] = '\0';
}

static void url_normalize(const char *src, char *dst, int dsz) {
    static const char hex[] = "0123456789ABCDEF";
    int o = 0;
    while (*src && o < dsz - 4) {
        unsigned char c = (unsigned char)*src;

        if (c == '%' && src[1] && src[2]) {
            int v = hex_byte(src[1], src[2]);
            if (v >= 0) {
                dst[o++] = '%';
                dst[o++] = hex[(v >> 4) & 0xF];
                dst[o++] = hex[v & 0xF];
                src += 3;
                continue;
            }
        }

        if ((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||
            c=='-'||c=='_'||c=='.'||c=='~'||
            c==':'||c=='/'||c=='?'||c=='#'||c=='@'||
            c=='!'||c=='$'||c=='&'||c=='\''||c=='('||c==')'||
            c=='*'||c=='+'||c==','||c==';'||c=='=') {
            dst[o++] = (char)c;
            src++;
            continue;
        }

        dst[o++] = '%';
        dst[o++] = hex[(c >> 4) & 0xF];
        dst[o++] = hex[c & 0xF];
        src++;
    }
    dst[o] = '\0';
}

static void url_prepare(const char *raw, char *out, int outsz) {
    char tmp[URL_MAX];
    url_decode(raw, tmp, sizeof(tmp));
    url_normalize(tmp, out, outsz);
}

static void url_prepare_lossless(const char *raw, char *out, int outsz) {
    /* Variante sin decode previo: preserva cualquier %XX ya presente y
     * solo codifica caracteres no seguros. Útil para URLs estilo navegador
     * donde decode+reencode puede alterar semántica en algunos backends. */
    url_normalize(raw ? raw : "", out, outsz);
}

static void extract_filename(const char *url, char *out, int outsz) {
    if (!url || !out || outsz <= 0) return;
    out[0] = '\0';
    const char *p = strrchr(url, '/');
    p = p ? p + 1 : url;
    int i = 0;
    while (p[i] && p[i] != '?' && p[i] != '#' && i < outsz - 1) {
        out[i] = p[i];
        i++;
    }
    out[i] = '\0';
}

static int resolve_primary_user_id(void) {
    /* En algunos entornos GoldHEN/firmware, BGFT rechaza user_id fijo.
     * Intentamos IDs reales del usuario logueado antes de usar fallback. */
    int32_t uid = getUserID();
    if (uid > 0) return uid;
    uid = getInitialUser();
    if (uid > 0) return uid;
    return 0x10000000;
}

/* ── BGFT runtime ──────────────────────────────────────────────────────── */
static int bgft_ensure(void) {
    if (bgft_loaded == -1) return -1;

    if (!bgft_loaded) {
        int _h = -1;
        int _ret = ps4_dynlib_load_prx("/system/common/lib/libSceBgft.sprx", 0, &_h, 0);
        int h = _h;

        if (h < 0) {
            snprintf(g_bgft_path, sizeof(g_bgft_path), "dlopen_failed:ret=0x%x h=%d", _ret, _h);
            bgft_loaded = -1;
            return -1;
        }

        getFunctionAddressByName(h, "sceBgftServiceInit", &fn_bgft_init);
        if (!fn_bgft_init)
            getFunctionAddressByName(h, "sceBgftServiceIntInit", &fn_bgft_init);

        getFunctionAddressByName(h, "sceBgftServiceDownloadStartTask", &fn_bgft_start);
        if (!fn_bgft_start)
            getFunctionAddressByName(h, "sceBgftDownloadStartTask", &fn_bgft_start);

        getFunctionAddressByName(h, "sceBgftServiceDownloadRegisterTask", &fn_bgft_reg);
        if (!fn_bgft_reg)
            getFunctionAddressByName(h, "sceBgftServiceDownloadRegisterTaskByStorageEx", &fn_bgft_reg);
        if (!fn_bgft_reg)
            getFunctionAddressByName(h, "sceBgftDownloadRegisterTaskByStorageEx", &fn_bgft_reg);
        if (!fn_bgft_reg)
            getFunctionAddressByName(h, "sceBgftDownloadRegisterTask", &fn_bgft_reg);

        snprintf(g_bgft_path, sizeof(g_bgft_path),
                 "dynlib:h=%d init=%s reg=%s start=%s",
                 h,
                 fn_bgft_init ? "ok" : "NULL",
                 fn_bgft_reg ? "ok" : "NULL",
                 fn_bgft_start ? "ok" : "NULL");

        if (!fn_bgft_init || !fn_bgft_reg || !fn_bgft_start) {
            bgft_loaded = -1;
            return -2;
        }
        bgft_loaded = 1;
    }

    if (bgft_inited != 1) {
        void *bgft_heap = mmap(NULL, 0x100000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (!bgft_heap || bgft_heap == MAP_FAILED) {
            snprintf(g_bgft_path, sizeof(g_bgft_path), "mmap_failed");
            bgft_loaded = -1;
            return -3;
        }

        int r = -1;
        bgft_init_params_t p;
        memset(&p, 0, sizeof(p));

        /* Compat firmware/SDK:
         * Algunos entornos esperan size=sizeof(struct), otros size=heap_size.
         * Probamos ambos layouts antes de fallar. */
        p.size = sizeof(bgft_init_params_t);
        p.mem  = bgft_heap;
        r = fn_bgft_init(&p);

        if (r != 0 && (uint32_t)r != 0x80990002u && (uint32_t)r != 0x80990004u) {
            p.size = 0x100000;
            p.mem  = bgft_heap;
            r = fn_bgft_init(&p);
        }

        if (r != 0 && (uint32_t)r != 0x80990002u && (uint32_t)r != 0x80990004u) {
            /* Último fallback: algunos payloads inicializan con mem=NULL */
            p.size = sizeof(bgft_init_params_t);
            p.mem  = NULL;
            r = fn_bgft_init(&p);
        }

        if (r != 0 && (uint32_t)r != 0x80990002u && (uint32_t)r != 0x80990004u) {
            char l[256];
            snprintf(l, sizeof(l), "bgft_init_fail r=0x%08x fw=%s", (uint32_t)r, g_fw_string);
            log_line(l);
            bgft_inited = r;
            return r;
        }
        bgft_inited = 1;
        {
            char l[256];
            snprintf(l, sizeof(l), "bgft_init_ok fw=%s", g_fw_string);
            log_line(l);
        }
    }

    return 0;
}

static int try_register_variant(bgft_task_param_t *p, int *task,
                                const char *url_candidate, uint32_t ent,
                                uint32_t uid, const char *tid,
                                const char *content_name, uint32_t opt) {
    last_reg_attempts++;
    p->content_url = url_candidate;
    p->entitlement_type = ent;
    p->user_id = uid;
    p->id = tid;
    p->content_name = content_name;
    p->option = opt;
    *task = -1;
    return fn_bgft_reg(p, task);
}

/* ── Install ───────────────────────────────────────────────────────────── */
static void do_install(int fd, const char *url_raw, const char *title, const char *name) {
    char url_norm[URL_MAX];
    char url_norm_lossless[URL_MAX];
    char url_raw_copy[URL_MAX];
    char auto_name[256];
    memset(url_norm, 0, sizeof(url_norm));
    memset(url_norm_lossless, 0, sizeof(url_norm_lossless));
    memset(url_raw_copy, 0, sizeof(url_raw_copy));
    memset(auto_name, 0, sizeof(auto_name));

    strncpy(url_raw_copy, url_raw ? url_raw : "", sizeof(url_raw_copy) - 1);
    url_prepare(url_raw_copy, url_norm, sizeof(url_norm));
    url_prepare_lossless(url_raw_copy, url_norm_lossless, sizeof(url_norm_lossless));

    if (!url_norm[0] && !url_norm_lossless[0] && !url_raw_copy[0]) {
        http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"URL vacia\"}");
        return;
    }

    const char *check = url_norm[0] ? url_norm : (url_norm_lossless[0] ? url_norm_lossless : url_raw_copy);
    if (strncmp(check, "http://", 7) != 0 && strncmp(check, "https://", 8) != 0) {
        http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"URL invalida (sin esquema http/https)\"}");
        return;
    }

    int r = bgft_ensure();
    if (r != 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "{\"status\":\"fail\",\"error\":\"BGFT no disponible (0x%08x)\"}", (uint32_t)r);
        http_send(fd, 500, msg);
        return;
    }

    bgft_task_param_t p;
    memset(&p, 0, sizeof(p));

    extract_filename(check, auto_name, sizeof(auto_name));

    const char *name0 = (name && name[0]) ? name : (auto_name[0] ? auto_name : "PKGSender Package");
    p.content_name = name0;
    p.option = BGFT_TASK_OPT_REMOTE | BGFT_TASK_OPT_DISABLE_CDN;

    static const char *tid_fallbacks[] = {
        "IV0000-PKGS00001_00-0000000000000000",
        "EP9000-CUSA00000_00-0000000000000000",
        "UP9000-CUSA00000_00-0000000000000000"
    };

    static const char *tid_relaxed[] = {
        NULL,
        ""
    };

    const char *tid0 = (title && title[0]) ? title : tid_fallbacks[0];
    int uid_primary = resolve_primary_user_id();
    last_user_id = uid_primary;

    int task = -1;
    int rr = -1;
    last_reg_attempts = 0;

    const uint32_t opt_variants[] = {
        BGFT_TASK_OPT_REMOTE | BGFT_TASK_OPT_DISABLE_CDN,
        BGFT_TASK_OPT_REMOTE,
        BGFT_TASK_OPT_NONE
    };

    const char *url_variants[3] = {
        url_norm[0] ? url_norm : NULL,
        url_norm_lossless[0] ? url_norm_lossless : NULL,
        url_raw_copy[0] ? url_raw_copy : NULL
    };

    for (int oi = 0; rr != 0 && oi < 3; oi++) {
        uint32_t opt = opt_variants[oi];

        for (int ui = 0; rr != 0 && ui < 3; ui++) {
            const char *u = url_variants[ui];
            if (!u) continue;

            rr = try_register_variant(&p, &task, u, 0, uid_primary, tid0, name0, opt);
            if (rr != 0) rr = try_register_variant(&p, &task, u, 5, uid_primary, tid0, name0, opt);
            if (rr != 0) rr = try_register_variant(&p, &task, u, 0, 0x10000000, tid0, name0, opt);
            if (rr != 0) rr = try_register_variant(&p, &task, u, 0, 1, tid0, name0, opt);

            for (int i = 1; rr != 0 && i < 3; i++) {
                rr = try_register_variant(&p, &task, u, 0, uid_primary, tid_fallbacks[i], name0, opt);
                if (rr != 0)
                    rr = try_register_variant(&p, &task, u, 5, uid_primary, tid_fallbacks[i], name0, opt);
            }

            for (int i = 0; rr != 0 && i < 2; i++) {
                rr = try_register_variant(&p, &task, u, 0, uid_primary, tid_relaxed[i], name0, opt);
                if (rr != 0)
                    rr = try_register_variant(&p, &task, u, 5, uid_primary, tid_relaxed[i], name0, opt);
                if (rr != 0)
                    rr = try_register_variant(&p, &task, u, 0, uid_primary, tid_relaxed[i], NULL, opt);
                if (rr != 0)
                    rr = try_register_variant(&p, &task, u, 5, uid_primary, tid_relaxed[i], NULL, opt);
            }
        }
    }

    last_bgft_rr = rr;

    if (rr == 0 && task >= 0) {
        fn_bgft_start(task);
        last_task = task;
                {
            char l[512];
            snprintf(l, sizeof(l), "install_ok task=%d uid=%u opt=0x%08x attempts=%d fw=%s", task, (uint32_t)p.user_id, p.option, last_reg_attempts, g_fw_string);
            log_line(l);
        }

        char resp[320];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"success\",\"task_id\":%d,\"title_id\":\"%s\",\"url\":\"%s\",\"option\":%u,\"user_id\":%u}",
            task, p.id ? p.id : "", p.content_url ? p.content_url : "", p.option, p.user_id);
        http_send(fd, 200, resp);
    } else {
                {
            char l[512];
            snprintf(l, sizeof(l), "install_fail rr=0x%08x uid=%u attempts=%d fw=%s url=%s", (uint32_t)rr, (uint32_t)uid_primary, last_reg_attempts, g_fw_string, check ? check : "");
            log_line(l);
        }
        char msg[320];
        snprintf(msg, sizeof(msg),
            "{\"status\":\"fail\",\"error\":\"bgft_reg 0x%08x\",\"bgft_path\":\"%s\",\"user_id\":%u,\"suggestion\":\"verifica usuario logueado en PS4, usa URL local directa y title_id/content_id valido\"}",
            (uint32_t)rr,
            g_bgft_path[0] ? g_bgft_path : "n/a",
            (uint32_t)uid_primary);
        http_send(fd, 500, msg);
        char notif[160];
        snprintf(notif, sizeof(notif), "PKGSender ERROR\nbgft_reg 0x%08x", (uint32_t)rr);
        notify(notif);
    }
}

/* ── Dispatcher ────────────────────────────────────────────────────────── */
static void handle_client(int fd) {
    char buf[BUF_MAX];
    memset(buf, 0, sizeof(buf));
    int n = recv_http(fd, buf, sizeof(buf));
    if (n <= 0) { sceNetSocketClose(fd); return; }

    if (strncmp(buf, "OPTIONS", 7) == 0) {
        http_send(fd, 204, "");
        sceNetSocketClose(fd);
        return;
    }

    if (strncmp(buf, "GET /ping", 9) == 0 || strncmp(buf, "GET / ", 6) == 0) {
        http_send(fd, 200,
            "{\"status\":\"success\",\"service\":\"ps4-pkgsender\",\"version\":\"7.21\",\"port\":12800}");
        sceNetSocketClose(fd);
        return;
    }

    if (strncmp(buf, "GET /api/fw", 11) == 0) {
        char resp[256];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"success\",\"firmware\":\"%s\",\"firmware_raw\":\"0x%08x\",\"log_path\":\"%s\"}",
            g_fw_string,
            g_fw_raw,
            g_log_path);
        http_send(fd, 200, resp);
        sceNetSocketClose(fd);
        return;
    }

    if (strncmp(buf, "GET /shutdown", 13) == 0) {
        http_send(fd, 200, "{\"status\":\"success\",\"message\":\"PKGSender detenido\"}");
        sceNetSocketClose(fd);
        notify("PKGSender\nDetenido — puerto 12800 libre");
        g_shutdown = 1;
        if (g_srv_fd >= 0) sceNetSocketClose(g_srv_fd);
        return;
    }

    if (strncmp(buf, "GET /api/status", 15) == 0 || strncmp(buf, "GET /status", 11) == 0) {
        char resp[256];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"success\",\"bgft_loaded\":%s,\"bgft_inited\":%s,\"last_task_id\":%d}",
            bgft_loaded == 1 ? "true" : "false",
            bgft_inited == 1 ? "true" : "false",
            last_task);
        http_send(fd, 200, resp);
        sceNetSocketClose(fd);
        return;
    }

    if (strncmp(buf, "GET /api/debug", 14) == 0) {
        if (bgft_loaded == -1) { bgft_loaded = 0; g_bgft_path[0] = '\0'; }
        int br = bgft_ensure();
        char resp[512];
        snprintf(resp, sizeof(resp),
            "{"
            "\"status\":\"success\","
            "\"version\":\"7.21\","
            "\"firmware\":\"%s\","
            "\"firmware_raw\":\"0x%08x\","
            "\"log_path\":\"%s\","
            "\"jailbreak\":\"0x%08x\","
            "\"bgft_loaded\":%s,"
            "\"bgft_inited\":%s,"
            "\"bgft_ensure\":\"0x%08x\","
            "\"bgft_path\":\"%s\","
            "\"last_bgft_reg\":\"0x%08x\","
            "\"last_reg_attempts\":%d,"
            "\"last_user_id\":%u,"
            "\"last_task_id\":%d"
            "}",
            g_fw_string,
            g_fw_raw,
            g_log_path,
            (uint32_t)g_jb_result,
            bgft_loaded == 1 ? "true" : "false",
            bgft_inited == 1 ? "true" : "false",
            (uint32_t)br,
            g_bgft_path[0] ? g_bgft_path : "not found",
            (uint32_t)last_bgft_rr,
            last_reg_attempts,
            (uint32_t)last_user_id,
            last_task);
        http_send(fd, 200, resp);
        sceNetSocketClose(fd);
        return;
    }

    char *body = strstr(buf, "\r\n\r\n");
    if (body) body += 4;
    else {
        body = strstr(buf, "\n\n");
        if (body) body += 2;
    }
    if (!body) body = (char *)"";
    {
        int blen = (int)strlen(body);
        while (blen > 0 && (body[blen-1] == '\r' || body[blen-1] == '\n' || body[blen-1] == ' '))
            body[--blen] = '\0';
    }

    if (strncmp(buf, "POST /api/is_exists", 19) == 0) {
        http_send(fd, 200, "{\"status\":\"success\",\"exists\":false,\"size\":0}");
        sceNetSocketClose(fd);
        return;
    }

    if (strstr(buf, "/api/get_task_progress") != NULL) {
        int req = *body ? json_int(body, "task_id", -1) : -1;
        char resp[256];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"success\",\"result\":-1,\"task_id\":%d,"
            "\"length\":0,\"transferred_length\":0,"
            "\"rest_sec\":0,\"preparing_percent\":50}",
            req >= 0 ? req : last_task);
        http_send(fd, 200, resp);
        sceNetSocketClose(fd);
        return;
    }

    if (strncmp(buf, "POST /install_url", 17) == 0) {
        if (!body || !body[0]) {
            http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"Body vacio: envia la URL como texto plano\"}");
            sceNetSocketClose(fd);
            return;
        }
        do_install(fd, body, "", "");
        sceNetSocketClose(fd);
        return;
    }

    if (strncmp(buf, "POST /api/install", 17) == 0) {
        if (!*body) {
            http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"Body vacio\"}");
            sceNetSocketClose(fd);
            return;
        }
        char url[URL_MAX] = {0}, title[64] = {0}, name[256] = {0};
        if (json_arr_first(body, "packages", url, sizeof(url)) <= 0)
            json_str(body, "url", url, sizeof(url));
        json_str(body, "title_id", title, sizeof(title));
        json_str(body, "name", name, sizeof(name));
        if (!url[0]) {
            http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"Sin URL en packages[]\"}");
            sceNetSocketClose(fd);
            return;
        }
        do_install(fd, url, title, name);
        sceNetSocketClose(fd);
        return;
    }

    if (strncmp(buf, "POST /install", 13) == 0) {
        if (!*body) {
            http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"Body vacio\"}");
            sceNetSocketClose(fd);
            return;
        }
        char url[URL_MAX] = {0}, title[64] = {0}, name[256] = {0};
        if (json_str(body, "url", url, sizeof(url)) <= 0)
            json_str(body, "pkg_url", url, sizeof(url));
        json_str(body, "title_id", title, sizeof(title));
        json_str(body, "name", name, sizeof(name));
        if (!name[0]) json_str(body, "title", name, sizeof(name));
        if (!url[0]) {
            http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"Campo url requerido\"}");
            sceNetSocketClose(fd);
            return;
        }
        do_install(fd, url, title, name);
        sceNetSocketClose(fd);
        return;
    }

    http_send(fd, 404,
        "{\"status\":\"fail\",\"error\":\"POST /install_url | POST /api/install | POST /install | GET /ping\"}");
    sceNetSocketClose(fd);
}

/* ── Entry point ───────────────────────────────────────────────────────── */
int _main(void) {
    initKernel();
    initLibc();
    initNetwork();
    initSysUtil();
    initModule();
    detect_firmware();

    int jb = jailbreak();
    g_jb_result = jb;
    if (jb < 0) {
        char notif[96];
        snprintf(notif, sizeof(notif), "PKGSender WARN\njailbreak() = 0x%08x", (uint32_t)jb);
        notify(notif);
    }

        {
        char l[256];
        snprintf(l, sizeof(l), "boot fw=%s fw_raw=0x%08x jailbreak=0x%08x", g_fw_string, g_fw_raw, (uint32_t)jb);
        log_line(l);
    }

    notify("PKGSender v7.21\nArrancando...");

    int srv = sceNetSocket("pkgsender_srv", AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        notify("PKGSender ERROR\nsceNetSocket fallo");
        return 1;
    }

    int opt = 1;
    sceNetSetsockopt(srv, SCE_NET_SOL_SOCKET, SCE_NET_SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = sceNetHtons(12800);
    addr.sin_addr.s_addr = IN_ADDR_ANY;

    if (sceNetBind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        sceNetSocketClose(srv);
        notify("PKGSender ERROR\nPuerto 12800 ocupado");
        return 1;
    }
    if (sceNetListen(srv, 8) < 0) {
        sceNetSocketClose(srv);
        notify("PKGSender ERROR\nlisten fallo");
        return 1;
    }

    g_srv_fd = srv;

    notify("PKGSender v7.21 ACTIVO\nPuerto :12800 listo\nPOST /install_url = URL plana");

    while (!g_shutdown) {
        struct sockaddr_in ca;
        unsigned int cl = sizeof(ca);
        int cfd = sceNetAccept(srv, (struct sockaddr *)&ca, &cl);
        if (cfd < 0) continue;
        handle_client(cfd);
    }

    notify("PKGSender\nPuerto 12800 liberado");
    return 0;
}
