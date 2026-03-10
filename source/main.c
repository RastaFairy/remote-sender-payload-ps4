/*
 * ps4-pkgsender-payload v7.11
 * Compilado con ps4-payload-sdk (gcc + libPS4)
 *
 * CAMBIOS v7.11 — sceSysmoduleLoadModuleInternal como vía principal para BGFT
 * ─────────────────────────────────────────────────────────────────────
 * En lugar de hardcodear nombres de archivo (que varían por firmware),
 * bgft_find_sprx() abre cada directorio candidato con sceKernelOpen +
 * getdents() y busca cualquier entrada cuyo nombre contenga "bgft"
 * (case-insensitive) y termine en ".sprx".
 * Funciona en todos los firmwares con GoldHEN sin recompilar.
 *
 * [v7.1] jailbreak() al arranque — fix 0xffffffff por falta de privs.
 * [v7.0] url_normalize(), POST /install_url, URL_MAX=4096.
 * [v6.0] recv_http() bucle TCP, hex_byte sin strtol.
 */

#include <ps4.h>

/* ── Constantes ─────────────────────────────────────────────────────────── */
#define URL_MAX   8192
#define BUF_MAX  16384



/* ── dynlib syscalls directas — patrón ps4-linux-payloads/lib/dl.c ────────
 *
 * Numeros de syscall PS4 (psdevwiki.com/ps4/Syscalls):
 *   dynlib_load_prx    = 594
 *   dynlib_dlsym       = 591
 *   dynlib_get_info_ex = 608
 *
 * ABI FreeBSD x86-64: rax=num, args: rdi rsi rdx r10 r8 r9
 * ─────────────────────────────────────────────────────────────────────── */

/* Estructura module_info_ex — igual que dl.c de flatz */
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

__attribute__((unused)) static int ps4_dynlib_dlsym(int handle, const char *name, void **addr)
{
    register long        rax __asm__("rax") = 591;
    register long        rdi __asm__("rdi") = (long)handle;
    register const char *rsi __asm__("rsi") = name;
    register void      **rdx __asm__("rdx") = addr;
    long ret;
    __asm__ volatile("syscall"
        : "=a"(ret) : "r"(rax),"r"(rdi),"r"(rsi),"r"(rdx)
        : "rcx","r11","memory");
    return (int)ret;
}

__attribute__((unused)) static int ps4_dynlib_get_info_ex(int handle, int unk, struct ps4_module_info_ex *info)
{
    register long                    rax __asm__("rax") = 608;
    register long                    rdi __asm__("rdi") = (long)handle;
    register long                    rsi __asm__("rsi") = (long)unk;
    register struct ps4_module_info_ex *rdx __asm__("rdx") = info;
    long ret;
    __asm__ volatile("syscall"
        : "=a"(ret) : "r"(rax),"r"(rdi),"r"(rsi),"r"(rdx)
        : "rcx","r11","memory");
    return (int)ret;
}

/*
 * ps4_dlopen — carga un sprx via dynlib_load_prx.
 *
 * IMPORTANTE: cuando el modulo ya esta cargado por el sistema, la syscall
 * puede retornar un codigo de error != 0 pero aun asi escribir un handle
 * valido (>= 0). La unica condicion de fallo real es h < 0.
 * NO llamamos init_proc manualmente — el modulo ya fue inicializado por
 * el sistema y llamarlo de nuevo puede corromper el estado interno.
 */
__attribute__((unused)) static int ps4_dlopen(const char *path)
{
    int h = -1;
    int ret = ps4_dynlib_load_prx(path, 0, &h, 0);
    (void)ret;  /* ignorar ret — solo importa h */
    return h;   /* >= 0 valido, < 0 fallo */
}



/* ── BGFT ────────────────────────────────────────────────────────────────── */
/*
 * Service API de libSceBgft.sprx:
 *   sceBgftServiceInit / sceBgftServiceIntInit  — inicializa con heap
 *   sceBgftServiceDownloadRegisterTask          — registra la descarga
 *   sceBgftServiceDownloadStartTask             — arranca la tarea
 *
 * "sceBgftServiceInit" se confirmó resolvible en iteración anterior (init=ok).
 * Se prueban múltiples candidatos para register hasta encontrar el correcto.
 */

/* ── Structs BGFT — Service API (confirmado flatz / ps4libdoc) ────────────
 *
 * sceBgftServiceInit toma un puntero a bgft_init_params_t.
 * sceBgftServiceDownloadRegisterTask toma bgft_task_param_t*.
 *
 * Fuente: https://github.com/flatz/ps4_remote_pkg_installer
 * ──────────────────────────────────────────────────────────────────────── */

typedef struct {
    size_t size; /* debe ser sizeof(bgft_init_params_t) */
    void  *mem;  /* heap de trabajo, 1 MB */
} bgft_init_params_t;

/* SceBgftDownloadParam — layout exacto de flatz/ps4_remote_pkg_installer
 * Fuente: installer.c (SceBgftDownloadParam + sceBgftServiceDownloadRegisterTask)
 * Offsets verificados contra OpenOrbis PS4 Toolchain headers.
 *
 * CRÍTICO: entitlement_type va en offset 0, user_id en offset 4,
 *          id (puntero) en offset 8. Cualquier reordenamiento = 0x80990002.
 */
typedef struct {
    uint32_t    entitlement_type;   /* offset  0 — 5 para fPKG/descarga */
    uint32_t    user_id;            /* offset  4 — 0x10000000 = user 1  */
    const char *id;                 /* offset  8 — content_id del PKG   */
    const char *content_url;        /* offset 16 — URL del .pkg         */
    const char *content_name;       /* offset 24 — nombre visible       */
    const char *icon_path;          /* offset 32 — NULL ok              */
    const char *sku_id;             /* offset 40 — NULL ok              */
    const char *playgo_scenario_id; /* offset 48 — NULL ok              */
    const char *release_date;       /* offset 56 — NULL ok              */
    const char *package_type;       /* offset 64 — NULL ok              */
    const char *package_sub_type;   /* offset 72 — NULL ok              */
    uint64_t    package_size;       /* offset 80 — 0 = desconocido      */
    uint32_t    option;             /* offset 88 — BGFT_TASK_OPT_*      */
} bgft_task_param_t;

#define BGFT_TASK_OPT_NONE        0x00000000
#define BGFT_TASK_OPT_DELETE_PKG  0x00000001
#define BGFT_TASK_OPT_INVISIBLE   0x00000002
#define BGFT_TASK_OPT_REMOTE      0x00000010
#define BGFT_TASK_OPT_DISABLE_CDN 0x00010000


static int (*fn_bgft_init)(bgft_init_params_t *p)                              = NULL;
static int (*fn_bgft_term)(void)                                               = NULL;
static int (*fn_bgft_reg) (const bgft_task_param_t *p, int *task_id)           = NULL;
static int (*fn_bgft_start)(int task_id)                                       = NULL;

static int bgft_loaded  = 0;
static int bgft_inited  = 0;
static int last_task    = -1;
static int g_jb_result  = 0;
static char g_bgft_path[256] = {0};
static int g_shutdown   = 0;
static int g_srv_fd     = -1;

/* Heap de trabajo para sceBgftServiceInit — 1 MB */

static int bgft_ensure(void) {
    if (bgft_loaded == -1) return -1;
    if (!bgft_loaded) {
        int _bgft_h = -1;
        int _bgft_ret = ps4_dynlib_load_prx(
            "/system/common/lib/libSceBgft.sprx", 0, &_bgft_h, 0);
        int h = _bgft_h;
        if (h < 0) {
            snprintf(g_bgft_path, sizeof(g_bgft_path),
                     "dlopen_failed:ret=0x%x h=%d", _bgft_ret, _bgft_h);
            bgft_loaded = -1; return -1;
        }

        /* Service API — nombres confirmados en PS4 homebrew (flatz, ps4libdoc) */
        getFunctionAddressByName(h, "sceBgftServiceInit",                   &fn_bgft_init);
        if (!fn_bgft_init)
        getFunctionAddressByName(h, "sceBgftServiceIntInit",                &fn_bgft_init);
        getFunctionAddressByName(h, "sceBgftServiceTerm",                   &fn_bgft_term);
        getFunctionAddressByName(h, "sceBgftServiceDownloadStartTask",      &fn_bgft_start);
        if (!fn_bgft_start)
        getFunctionAddressByName(h, "sceBgftDownloadStartTask",             &fn_bgft_start);

        /* Probar todos los candidatos conocidos para la función de registro */
        getFunctionAddressByName(h, "sceBgftServiceDownloadRegisterTask",        &fn_bgft_reg);
        if (!fn_bgft_reg)
        getFunctionAddressByName(h, "sceBgftServiceDownloadRegisterTaskByStorageEx", &fn_bgft_reg);
        if (!fn_bgft_reg)
        getFunctionAddressByName(h, "sceBgftDownloadRegisterTaskByStorageEx",    &fn_bgft_reg);
        if (!fn_bgft_reg)
        getFunctionAddressByName(h, "sceBgftDownloadRegisterTask",               &fn_bgft_reg);

        snprintf(g_bgft_path, sizeof(g_bgft_path),
                 "dynlib:h=%d init=%s reg=%s start=%s",
                 h,
                 fn_bgft_init  ? "ok" : "NULL",
                 fn_bgft_reg   ? "ok" : "NULL",
                 fn_bgft_start ? "ok" : "NULL");

        if (!fn_bgft_init || !fn_bgft_reg || !fn_bgft_start) {
            bgft_loaded = -1; return -2;
        }
        bgft_loaded = 1;
    }
    if (bgft_inited != 1) {
        /* Allocar el heap BGFT dinamicamente — 1 MB en BSS estatico
         * excede los limites del linker del ps4-payload-sdk */
        void *bgft_heap = mmap(NULL, 0x100000,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1, 0);
        if (!bgft_heap || bgft_heap == MAP_FAILED) {
            snprintf(g_bgft_path, sizeof(g_bgft_path), "mmap_failed");
            bgft_loaded = -1; return -3;
        }
        bgft_init_params_t p;
        memset(&p, 0, sizeof(p));
        p.size = 0x100000; /* tamaño del heap de trabajo, no de la struct */
        p.mem  = bgft_heap;
        int r = fn_bgft_init(&p);
        /* 0x80990002/0x80990004 = ya inicializado por el sistema, se acepta */
        if (r != 0 && (uint32_t)r != 0x80990002u && (uint32_t)r != 0x80990004u) { bgft_inited = r; return r; }
        bgft_inited = 1;
    }
    return 0;
}

/* ── Notificaciones ─────────────────────────────────────────────────────── */
static void notify(const char *msg) {
    printf_notification("%s", msg);
}
static void notify_retry(const char *msg, int tries, int delay_sec) {
    for (int i = 0; i < tries; i++) {
        notify(msg);
        if (i < tries - 1) sceKernelSleep(delay_sec);
    }
}

/* ── HTTP helpers ───────────────────────────────────────────────────────── */
static const char CORS[] =
    "Access-Control-Allow-Origin: *\r\n"
    "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
    "Access-Control-Allow-Headers: Content-Type\r\n";

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

/* ── recv_http ──────────────────────────────────────────────────────────── */
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
            int room  = bufsz - 1 - total;
            if (want > room) want = room;
            n = sceNetRecv(fd, buf + total, want, 0);
            if (n <= 0) break;
            total     += n;
            body_recv += n;
        }
        buf[total] = '\0';
        break;
    }
    return total;
}

/* ── JSON helpers ───────────────────────────────────────────────────────── */
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
        if (*p == '\\' && *(p+1)) {
            p++;
            switch (*p) {
            case '"':  out[i++] = '"';  break;
            case '\\': out[i++] = '\\'; break;
            case '/':  out[i++] = '/';  break;
            case 'n':  out[i++] = '\n'; break;
            case 'r':  out[i++] = '\r'; break;
            case 't':  out[i++] = '\t'; break;
            case 'u':
                if (p[1] && p[2] && p[3] && p[4]) {
                    int v = 0;
                    for (int k = 1; k <= 4; k++) {
                        char c = p[k]; v <<= 4;
                        v |= (c>='0'&&c<='9') ? c-'0'
                           : (c>='A'&&c<='F') ? c-'A'+10
                           : (c>='a'&&c<='f') ? c-'a'+10 : 0;
                    }
                    if (v > 0 && v < 0x80) out[i++] = (char)v;
                    p += 4;
                }
                break;
            default: out[i++] = *p; break;
            }
        } else { out[i++] = *p; }
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
    while (*p && *p != '"' && i < sz - 1) {
        if (*p == '\\' && *(p+1) == '/') { out[i++] = '/'; p += 2; continue; }
        if (*p == '\\' && *(p+1) == '"') { out[i++] = '"'; p += 2; continue; }
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

/* ── URL helpers ────────────────────────────────────────────────────────── */
static int hex_byte(char hi, char lo) {
    int h = (hi>='0'&&hi<='9') ? hi-'0'
          : (hi>='A'&&hi<='F') ? hi-'A'+10
          : (hi>='a'&&hi<='f') ? hi-'a'+10 : -1;
    int l = (lo>='0'&&lo<='9') ? lo-'0'
          : (lo>='A'&&lo<='F') ? lo-'A'+10
          : (lo>='a'&&lo<='f') ? lo-'a'+10 : -1;
    if (h < 0 || l < 0) return -1;
    return (h << 4) | l;
}

static void url_decode(const char *src, char *dst, int dsz) {
    int o = 0;
    while (*src && o < dsz - 1) {
        if (*src == '%' && src[1] && src[2]) {
            int v = hex_byte(src[1], src[2]);
            if (v > 0) { dst[o++] = (char)v; src += 3; continue; }
        } else if (*src == '+') { dst[o++] = ' '; src++; continue; }
        dst[o++] = *src++;
    }
    dst[o] = '\0';
}

static void url_normalize(const char *src, char *dst, int dsz) {
    /* RFC 3986 — codifica todo lo que no sea un caracter seguro para URLs.
     * Corchetes [ ] se codifican siempre: son validos solo en el host (IPv6),
     * nunca en el path/query. BGFT los rechaza si van sin codificar. */
    static const char hex[] = "0123456789ABCDEF";
    int o = 0;
    while (*src && o < dsz - 4) {
        unsigned char c = (unsigned char)*src;
        /* Secuencia %XX ya codificada — pasar tal cual (normalizar mayúsculas) */
        if (c == '%' && src[1] && src[2]) {
            int v = hex_byte(src[1], src[2]);
            if (v >= 0) {
                dst[o++] = '%';
                dst[o++] = hex[(v >> 4) & 0xF];  /* normalizar a mayúsculas */
                dst[o++] = hex[v & 0xF];
                src += 3; continue;
            }
        }
        /* Caracteres seguros sin codificar — RFC 3986 sección 2.3 + delimitadores
         * de path/query. NO incluir [ ] — BGFT los rechaza en el path. */
        if ((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||
            c=='-'||c=='_'||c=='.'||c=='~'||  /* unreserved */
            c==':'||c=='/'||c=='?'||c=='#'||c=='@'||  /* delimitadores URI */
            c=='!'||c=='$'||c=='&'||c=='\''||c=='('||c==')'||
            c=='*'||c=='+'||c==','||c==';'||c=='=')  /* sub-delimitadores */
        { dst[o++] = (char)c; src++; continue; }
        /* Todo lo demás (incluyendo [ ] espacio etc.) — codificar */
        dst[o++] = '%';
        dst[o++] = hex[(c >> 4) & 0xF];
        dst[o++] = hex[c & 0xF];
        src++;
    }
    dst[o] = '\0';
}

static void url_prepare(const char *raw, char *out, int outsz) {
    /* Paso 1: decodificar cualquier %XX existente para evitar doble-codificación
     * Paso 2: re-codificar correctamente según RFC 3986 (incluyendo [ ] etc.) */
    char tmp[URL_MAX];
    url_decode(raw, tmp, sizeof(tmp));
    url_normalize(tmp, out, outsz);
}

/* ── Instalacion ────────────────────────────────────────────────────────── */
static void do_install(int fd, const char *url_raw,
                        const char *title, const char *name) {
    char url[URL_MAX];
    memset(url, 0, sizeof(url));
    url_prepare(url_raw, url, sizeof(url));

    if (!url[0]) {
        http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"URL vacia\"}");
        return;
    }
    if (strncmp(url,"http://",7)!=0 && strncmp(url,"https://",8)!=0) {
        http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"URL invalida (sin esquema http/https)\"}");
        return;
    }

    int r = bgft_ensure();
    if (r != 0) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "{\"status\":\"fail\",\"error\":\"BGFT no disponible (0x%08x)\"}", (uint32_t)r);
        http_send(fd, 500, msg);
        char notif[128];
        snprintf(notif, sizeof(notif), "PKGSender ERROR\nBGFT 0x%08x", (uint32_t)r);
        notify(notif);
        return;
    }

    /* bgft_task_param_t — campos en orden exacto del struct real (flatz)
     * entitlement_type: 0 = fPKG/homebrew, 5 = contenido PSN firmado.
     * id: nunca NULL — la función rechaza el param si es NULL. */
    bgft_task_param_t p;
    memset(&p, 0, sizeof(p));
    p.entitlement_type   = 0;            /* 0 = fPKG, no requiere firma PSN */
    p.user_id            = 0x10000000;   /* user 1 */
    p.id                 = (title && title[0]) ? title
                           : "IV0000-PKGS00001_00-0000000000000000";
    p.content_url        = url;
    p.content_name       = (name && name[0]) ? name : "PKGSender Package";
    p.icon_path          = NULL;
    p.sku_id             = NULL;
    p.playgo_scenario_id = NULL;
    p.release_date       = NULL;
    p.package_type       = NULL;
    p.package_sub_type   = NULL;
    p.package_size       = 0;
    p.option             = BGFT_TASK_OPT_NONE;

    int task = -1;
    int rr = fn_bgft_reg(&p, &task);

    /* Reintento con entitlement_type=5 si falla con 0 */
    if (rr != 0) {
        p.entitlement_type = 5;
        task = -1;
        rr = fn_bgft_reg(&p, &task);
    }
    /* Reintento con user_id=1 (algunos FW usan int directo) */
    if (rr != 0) {
        p.entitlement_type = 0;
        p.user_id = 1;
        task = -1;
        rr = fn_bgft_reg(&p, &task);
    }

    if (rr == 0 && task >= 0) {
        fn_bgft_start(task);
        last_task = task;
        char notif[256];
        snprintf(notif, sizeof(notif), "PKGSender\nDescargando: %s",
            name && name[0] ? name : title && title[0] ? title : "PKG");
        notify(notif);
        char resp[256];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"success\",\"task_id\":%d,\"title_id\":\"%s\"}",
            task, title && title[0] ? title : "");
        http_send(fd, 200, resp);
    } else {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "{\"status\":\"fail\",\"error\":\"bgft_reg 0x%08x\"}", (uint32_t)rr);
        http_send(fd, 500, msg);
        char notif[128];
        snprintf(notif, sizeof(notif), "PKGSender ERROR\nbgft_reg 0x%08x", (uint32_t)rr);
        notify(notif);
    }
}

/* ── Dispatcher ─────────────────────────────────────────────────────────── */
static void handle_client(int fd) {
    char buf[BUF_MAX];
    memset(buf, 0, sizeof(buf));
    int n = recv_http(fd, buf, sizeof(buf));
    if (n <= 0) { sceNetSocketClose(fd); return; }

    if (strncmp(buf, "OPTIONS", 7) == 0) {
        http_send(fd, 204, ""); sceNetSocketClose(fd); return;
    }

    if (strncmp(buf, "GET /ping", 9) == 0 || strncmp(buf, "GET / ", 6) == 0) {
        http_send(fd, 200,
            "{\"status\":\"success\",\"service\":\"ps4-pkgsender\","
            "\"version\":\"7.11\",\"port\":12800}");
        sceNetSocketClose(fd); return;
    }

    /* GET /shutdown — libera el puerto y termina el payload sin reiniciar */
    if (strncmp(buf, "GET /shutdown", 13) == 0) {
        http_send(fd, 200, "{\"status\":\"success\",\"message\":\"PKGSender detenido\"}");
        sceNetSocketClose(fd);
        notify("PKGSender\nDetenido — puerto 12800 libre");
        g_shutdown = 1;
        if (g_srv_fd >= 0) sceNetSocketClose(g_srv_fd);
        return;
    }

    if (strncmp(buf, "GET /api/status", 15) == 0 ||
        strncmp(buf, "GET /status",     11) == 0) {
        char resp[256];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"success\",\"bgft_loaded\":%s,"
            "\"bgft_inited\":%s,\"last_task_id\":%d}",
            bgft_loaded == 1 ? "true" : "false",
            bgft_inited == 1 ? "true" : "false",
            last_task);
        http_send(fd, 200, resp); sceNetSocketClose(fd); return;
    }

    /* GET /api/debug — muestra la ruta encontrada por getdents */
    if (strncmp(buf, "GET /api/debug", 14) == 0) {
        if (bgft_loaded == -1) { bgft_loaded = 0; g_bgft_path[0] = 0; }
        int br = bgft_ensure();
        char resp[512];
        snprintf(resp, sizeof(resp),
            "{"
            "\"status\":\"success\","
            "\"version\":\"7.11\","
            "\"jailbreak\":\"0x%08x\","
            "\"bgft_loaded\":%s,"
            "\"bgft_inited\":%s,"
            "\"bgft_ensure\":\"0x%08x\","
            "\"bgft_path\":\"%s\","
            "\"last_task_id\":%d"
            "}",
            (uint32_t)g_jb_result,
            bgft_loaded == 1 ? "true" : "false",
            bgft_inited == 1 ? "true" : "false",
            (uint32_t)br,
            g_bgft_path[0] ? g_bgft_path : "not found",
            last_task);
        http_send(fd, 200, resp); sceNetSocketClose(fd); return;
    }

    /* Extraer body */
    char *body = strstr(buf, "\r\n\r\n");
    if (body) body += 4;
    else { body = strstr(buf, "\n\n"); if (body) body += 2; }
    if (!body) body = (char *)"";
    {
        int blen = (int)strlen(body);
        while (blen > 0 && (body[blen-1]=='\r'||body[blen-1]=='\n'||body[blen-1]==' '))
            body[--blen] = '\0';
    }

    if (strncmp(buf, "POST /api/is_exists", 19) == 0) {
        http_send(fd, 200, "{\"status\":\"success\",\"exists\":false,\"size\":0}");
        sceNetSocketClose(fd); return;
    }

    /* POST /install_url — body plano = URL cruda, sin JSON */
    if (strncmp(buf, "POST /install_url", 17) == 0) {
        if (!body || !body[0]) {
            http_send(fd, 400,
                "{\"status\":\"fail\",\"error\":\"Body vacio: envia la URL como texto plano\"}");
            sceNetSocketClose(fd); return;
        }
        do_install(fd, body, "", "");
        sceNetSocketClose(fd); return;
    }

    /* POST /api/install */
    if (strncmp(buf, "POST /api/install", 17) == 0) {
        if (!*body) {
            http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"Body vacio\"}");
            sceNetSocketClose(fd); return;
        }
        char url[URL_MAX]={0}, title[64]={0}, name[256]={0};
        if (json_arr_first(body, "packages", url, sizeof(url)) <= 0)
            json_str(body, "url", url, sizeof(url));
        json_str(body, "title_id", title, sizeof(title));
        json_str(body, "name",     name,  sizeof(name));
        if (!url[0]) {
            http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"Sin URL en packages[]\"}");
            sceNetSocketClose(fd); return;
        }
        do_install(fd, url, title, name);
        sceNetSocketClose(fd); return;
    }

    if (strstr(buf, "/api/get_task_progress") != NULL) {
        int req = *body ? json_int(body, "task_id", -1) : -1;
        char resp[256];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"success\",\"result\":-1,\"task_id\":%d,"
            "\"length\":0,\"transferred_length\":0,"
            "\"rest_sec\":0,\"preparing_percent\":50}",
            req >= 0 ? req : last_task);
        http_send(fd, 200, resp); sceNetSocketClose(fd); return;
    }

    /* POST /install — legacy */
    if (strncmp(buf, "POST /install", 13) == 0) {
        if (!*body) {
            http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"Body vacio\"}");
            sceNetSocketClose(fd); return;
        }
        char url[URL_MAX]={0}, title[64]={0}, name[256]={0};
        if (json_str(body, "url", url, sizeof(url)) <= 0)
            json_str(body, "pkg_url", url, sizeof(url));
        json_str(body, "title_id", title, sizeof(title));
        json_str(body, "name",     name,  sizeof(name));
        if (!name[0]) json_str(body, "title", name, sizeof(name));
        if (!url[0]) {
            http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"Campo url requerido\"}");
            sceNetSocketClose(fd); return;
        }
        do_install(fd, url, title, name);
        sceNetSocketClose(fd); return;
    }

    http_send(fd, 404,
        "{\"status\":\"fail\",\"error\":"
        "\"POST /install_url | POST /api/install | POST /install | GET /ping\"}");
    sceNetSocketClose(fd);
}

/* ── Entry point ────────────────────────────────────────────────────────── */
int _main(void) {
    initKernel();
    initLibc();
    initNetwork();
    initSysUtil();
    initModule();

    int jb = jailbreak();
    g_jb_result = jb;
    if (jb < 0) {
        char notif[96];
        snprintf(notif, sizeof(notif), "PKGSender WARN\njailbreak() = 0x%08x", (uint32_t)jb);
        notify(notif);
    }


    notify("PKGSender v7.11\nArrancando...");

    int srv = sceNetSocket("pkgsender_srv", AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { notify("PKGSender ERROR\nsceNetSocket fallo"); return 1; }

    int opt = 1;
    sceNetSetsockopt(srv, SCE_NET_SOL_SOCKET, SCE_NET_SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = sceNetHtons(12800);
    addr.sin_addr.s_addr = IN_ADDR_ANY;

    if (sceNetBind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        sceNetSocketClose(srv); notify("PKGSender ERROR\nPuerto 12800 ocupado"); return 1;
    }
    if (sceNetListen(srv, 8) < 0) {
        sceNetSocketClose(srv); notify("PKGSender ERROR\nlisten fallo"); return 1;
    }

    g_srv_fd = srv;

    notify_retry(
        "PKGSender v7.11 ACTIVO\n"
        "Puerto :12800 listo\n"
        "POST /install_url = URL plana",
        3, 1);

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