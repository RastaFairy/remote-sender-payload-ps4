#include <ps4.h>

/* ────────────────────────────────────────────────────────────────────────────
 * Constantes
 * ──────────────────────────────────────────────────────────────────────── */
#define TMP_PKG    "/user/data/pkgsender_tmp.pkg"
#define LOG_PATH   "/data/pkgsender.log"
#define DNS_SERVER "8.8.8.8"   /* Google DNS — fallback si la PS4 no resuelve */
#define DNS_ALT    "1.1.1.1"   /* Cloudflare DNS — segundo intento */
#define URL_MAX    4096
#define BUF_MAX    16384

/* Credenciales S3 de archive.org para descargas autenticadas.
 * Header: Authorization: LOW <access>:<secret>
 * Se añade solo cuando el host contiene "archive.org" o "ia*.us.archive.org" */
#define ARCHIVEORG_S3_ACCESS "qua6Rg7cceGmwzXk"
#define ARCHIVEORG_S3_SECRET "WhWXvlYJhCrkAUbg"
#define ARCHIVEORG_S3_AUTH   "LOW " ARCHIVEORG_S3_ACCESS ":" ARCHIVEORG_S3_SECRET

/* ────────────────────────────────────────────────────────────────────────────
 * Syscall 594: dynlib_load_prx  (carga un .sprx por ruta)
 * ──────────────────────────────────────────────────────────────────────── */
static int ps4_dynlib_load_prx(const char *path, int flags, int *h, int z)
{
    register long        rax __asm__("rax") = 594;
    register const char *rdi __asm__("rdi") = path;
    register long        rsi __asm__("rsi") = (long)flags;
    register int        *rdx __asm__("rdx") = h;
    register long        r10 __asm__("r10") = (long)z;
    long ret;
    __asm__ volatile("syscall"
        : "=a"(ret)
        : "r"(rax),"r"(rdi),"r"(rsi),"r"(rdx),"r"(r10)
        : "rcx","r11","memory");
    return (int)ret;
}

/* ────────────────────────────────────────────────────────────────────────────
 * Syscall 480: ftruncate  (pre-aloca espacio en disco)
 * ──────────────────────────────────────────────────────────────────────── */
static int ps4_ftruncate(int fd, int64_t len)
{
    register long rax __asm__("rax") = 480;
    register long rdi __asm__("rdi") = (long)fd;
    register long rsi __asm__("rsi") = len;
    long ret;
    __asm__ volatile("syscall"
        : "=a"(ret)
        : "r"(rax),"r"(rdi),"r"(rsi)
        : "rcx","r11","memory");
    return (int)(ret < 0 ? ret : 0);
}

/* ────────────────────────────────────────────────────────────────────────────
 * AppInstUtil — carga lazy de libSceAppInstUtil.sprx
 * ──────────────────────────────────────────────────────────────────────── */
static int (*fn_init)   (void)                                     = NULL;
static int (*fn_install)(const char *path, int r)                  = NULL;
static int (*fn_gettid) (const char *path, char *tid, int *is_app) = NULL;
static int (*fn_prepare)(const char *path)                         = NULL;

static int  g_ai_loaded = 0;
static char g_ai_detail[128] = "not_loaded";

static int ai_ensure(void)
{
    if (g_ai_loaded ==  1) return 0;
    if (g_ai_loaded == -1) return -1;
    int h = -1;
    ps4_dynlib_load_prx("/system/common/lib/libSceAppInstUtil.sprx", 0, &h, 0);
    if (h < 0) {
        snprintf(g_ai_detail, sizeof(g_ai_detail), "dlopen_fail h=%d", h);
        g_ai_loaded = -1; return -1;
    }
    static char s1[] = "sceAppInstUtilInitialize";
    static char s2[] = "sceAppInstUtilAppInstallPkg";
    static char s3[] = "sceAppInstUtilGetTitleIdFromPkg";
    static char s4[] = "sceAppInstUtilAppPrepareOverwritePkg";
    getFunctionAddressByName(h, s1, &fn_init);
    getFunctionAddressByName(h, s2, &fn_install);
    getFunctionAddressByName(h, s3, &fn_gettid);
    getFunctionAddressByName(h, s4, &fn_prepare);
    snprintf(g_ai_detail, sizeof(g_ai_detail),
             "h=%d init=%s install=%s",
             h, fn_init?"ok":"NULL", fn_install?"ok":"NULL");
    if (!fn_install) { g_ai_loaded = -1; return -2; }
    if (fn_init) fn_init();
    g_ai_loaded = 1; return 0;
}

/* ────────────────────────────────────────────────────────────────────────────
 * Estado global
 * ──────────────────────────────────────────────────────────────────────── */
static char     g_fw[64]        = "unknown";
static uint32_t g_fw_raw        = 0;
static int      g_last_inst     = 0;
static int      g_last_bytes    = 0;
static char     g_last_url[256] = {0};
static char     g_last_st[32]   = "idle";
static int      g_gsched        = -999;
static int      g_ffsalloc      = -999;
static int      g_srv_fd        = -1;
static int      g_shutdown      = 0;
static volatile int64_t g_dl_bytes_done  = 0;
static volatile int64_t g_dl_bytes_total = 0;
static volatile int     g_dl_pct         = 0;
static char             g_dl_name[64]    = {0};
static uint8_t          g_bgft_mem[0x10000];  /* 64KB para BGFT */

/* ────────────────────────────────────────────────────────────────────────────
 * Log a disco
 * ──────────────────────────────────────────────────────────────────────── */
static void log_line(const char *s)
{
    FILE *f = fopen(LOG_PATH, "a");
    if (!f) return;
    fprintf(f, "%s\n", s ? s : "");
    fclose(f);
}

/* ────────────────────────────────────────────────────────────────────────────
 * HTTP helpers
 * ──────────────────────────────────────────────────────────────────────── */
static const char CORS[] =
    "Access-Control-Allow-Origin: *\r\n"
    "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
    "Access-Control-Allow-Headers: Content-Type\r\n";

static void notify(const char *msg) { printf_notification("%s", msg); }

static void http_send(int fd, int code, const char *body)
{
    const char *st = code==200?"OK" : code==204?"No Content" :
                     code==400?"Bad Request" : code==404?"Not Found" :
                     "Internal Server Error";
    char hdr[512];
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Content-Length: %d\r\n%s"
        "Connection: close\r\n\r\n",
        code, st, (int)strlen(body), CORS);
    sceNetSend(fd, hdr, hlen, 0);
    if (body[0]) sceNetSend(fd, body, strlen(body), 0);
}

/* ────────────────────────────────────────────────────────────────────────────
 * bgft_create_fake_task
 *
 * Crea la entrada en /user/bgft/task/<id>/ con d0.pdb y d1.pdb para que
 * sceBgftNotifyGameWillStart encuentre el task al lanzar el juego.
 *
 * El content_id se extrae del header del PKG (offset 0x40, 36 bytes).
 * El title_id se obtiene de sceAppInstUtilGetTitleIdFromPkg.
 *
 * El task ID se toma del archivo /user/bgft/task_id_count si existe,
 * o se usa 0x0FFFFF como fallback (suficientemente alto para no colisionar).
 * ──────────────────────────────────────────────────────────────────────── */

/* Template pdb (999 bytes) extraído de task real de BGFT.
 * Campos variables (longitud FIJA en el template):
 *   content_id: offset 0x0dc, 36 bytes
 *   title_id:   offset 0x10c,  9 bytes
 *   inst_path:  offset 0x298, 27 bytes  "/user/app/PKGI12345/app.pkg"
 */
#define PDB_SIZE        999
#define PDB_CID_OFF     0x0dc
#define PDB_TID_OFF     0x10c
#define PDB_PATH_OFF    0x298

static const uint8_t s_pdb_template[PDB_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x01, 0x80, 0x50, 0x12, 0x8b, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x8e, 0xe4, 0x1b, 0xaa,
    0x1f, 0x05, 0xe3, 0x00, 0x64, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x6b, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
    0x65, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x68, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x6c, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x6d, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x76, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x0c, 0x66, 0xb8, 0x97, 0x1f, 0x05, 0xe3, 0x00,
    0x90, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
    0x24, 0x00, 0x00, 0x00, 0x45, 0x44, 0x31, 0x37, 0x33, 0x33, 0x2d, 0x50,
    0x4b, 0x47, 0x49, 0x31, 0x32, 0x33, 0x34, 0x35, 0x5f, 0x30, 0x30, 0x2d,
    0x43, 0x49, 0x42, 0x4f, 0x52, 0x47, 0x45, 0x43, 0x50, 0x4b, 0x47, 0x4d,
    0x41, 0x4e, 0x30, 0x31, 0x7c, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
    0x09, 0x00, 0x00, 0x00, 0x50, 0x4b, 0x47, 0x49, 0x31, 0x32, 0x33, 0x34,
    0x35, 0x9a, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x75, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
    0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x92, 0x01, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x30, 0x93, 0x01,
    0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x70, 0x00, 0x00, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x9d, 0x01,
    0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x95, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x03, 0x90, 0x13, 0x00, 0x00, 0xcc, 0x00, 0x00, 0x00, 0xcc,
    0x00, 0x00, 0x00, 0x7b, 0x22, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x4f,
    0x66, 0x53, 0x70, 0x6c, 0x69, 0x74, 0x46, 0x69, 0x6c, 0x65, 0x73, 0x22,
    0x3a, 0x31, 0x2c, 0x22, 0x70, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x44,
    0x69, 0x67, 0x65, 0x73, 0x74, 0x22, 0x3a, 0x22, 0x35, 0x41, 0x31, 0x35,
    0x45, 0x34, 0x31, 0x32, 0x44, 0x33, 0x39, 0x30, 0x39, 0x39, 0x37, 0x30,
    0x45, 0x45, 0x37, 0x44, 0x35, 0x41, 0x41, 0x38, 0x34, 0x38, 0x38, 0x44,
    0x30, 0x42, 0x36, 0x41, 0x46, 0x41, 0x45, 0x38, 0x31, 0x38, 0x35, 0x37,
    0x38, 0x45, 0x34, 0x45, 0x42, 0x37, 0x36, 0x43, 0x46, 0x37, 0x37, 0x37,
    0x30, 0x37, 0x31, 0x31, 0x35, 0x42, 0x38, 0x36, 0x36, 0x34, 0x39, 0x34,
    0x22, 0x2c, 0x22, 0x70, 0x69, 0x65, 0x63, 0x65, 0x73, 0x22, 0x3a, 0x5b,
    0x7b, 0x22, 0x66, 0x69, 0x6c, 0x65, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74,
    0x22, 0x3a, 0x30, 0x2c, 0x22, 0x66, 0x69, 0x6c, 0x65, 0x53, 0x69, 0x7a,
    0x65, 0x22, 0x3a, 0x37, 0x37, 0x37, 0x32, 0x35, 0x36, 0x39, 0x36, 0x2c,
    0x22, 0x75, 0x72, 0x6c, 0x22, 0x3a, 0x22, 0x5c, 0x2f, 0x6d, 0x6e, 0x74,
    0x5c, 0x2f, 0x64, 0x69, 0x73, 0x63, 0x5c, 0x2f, 0x50, 0x53, 0x34, 0x43,
    0x69, 0x62, 0x6f, 0x72, 0x67, 0x45, 0x63, 0x50, 0x4b, 0x47, 0x4d, 0x41,
    0x4e, 0x2d, 0x76, 0x32, 0x2e, 0x30, 0x36, 0x2e, 0x70, 0x6b, 0x67, 0x22,
    0x7d, 0x5d, 0x7d, 0x88, 0x13, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x25,
    0x00, 0x00, 0x00, 0x2f, 0x6d, 0x6e, 0x74, 0x2f, 0x64, 0x69, 0x73, 0x63,
    0x2f, 0x50, 0x53, 0x34, 0x43, 0x69, 0x62, 0x6f, 0x72, 0x67, 0x45, 0x63,
    0x50, 0x4b, 0x47, 0x4d, 0x41, 0x4e, 0x2d, 0x76, 0x32, 0x2e, 0x30, 0x36,
    0x2e, 0x70, 0x6b, 0x67, 0x89, 0x13, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00,
    0x1b, 0x00, 0x00, 0x00, 0x2f, 0x75, 0x73, 0x65, 0x72, 0x2f, 0x61, 0x70,
    0x70, 0x2f, 0x50, 0x4b, 0x47, 0x49, 0x31, 0x32, 0x33, 0x34, 0x35, 0x2f,
    0x61, 0x70, 0x70, 0x2e, 0x70, 0x6b, 0x67, 0x94, 0x01, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0xf4, 0x01, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x69, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00,
    0x50, 0x53, 0x34, 0x43, 0x69, 0x62, 0x6f, 0x72, 0x67, 0x45, 0x63, 0x50,
    0x4b, 0x47, 0x4d, 0x41, 0x4e, 0x2d, 0x76, 0x32, 0x2e, 0x30, 0x36, 0x2e,
    0x70, 0x6b, 0x67, 0xa3, 0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xa2, 0x04, 0x00, 0x00, 0x00, 0x00, 0x7a,
    0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xa2, 0x04, 0x00, 0x00, 0x00, 0x00, 0xa4, 0x01, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x69, 0x04, 0x00, 0x00, 0xb4,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb5,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb6,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff,
    0xff, 0xff, 0xff, 0xb7, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xbb, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xb9,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9a,
    0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x91, 0x01, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0xa6,
    0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x7b, 0x00, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa2, 0x04, 0x00,
    0x00, 0x00, 0x00
};

/* Escribe d0.pdb y d1.pdb con content_id y title_id del PKG.
 * content_id: 36 bytes desde offset 0x40 del PKG header.
 * Devuelve 0 si OK, -1 si error. */
static int bgft_create_fake_task(const char *pkg_path, const char *title_id)
{
    /* Leer content_id del PKG (offset 0x40, 36 bytes ASCII) */
    char content_id[37] = {0};
    {
        int pkgfd = open(pkg_path, O_RDONLY, 0);
        if (pkgfd < 0) {
            log_line("bgft_fake: cannot open pkg");
            return -1;
        }
        lseek(pkgfd, 0x40, 0);  /* SEEK_SET=0 */
        read(pkgfd, content_id, 36);
        close(pkgfd);
        content_id[36] = '\0';
    }
    if (content_id[0] == '\0') {
        log_line("bgft_fake: content_id empty");
        return -1;
    }
    {
        char l[80];
        snprintf(l, sizeof(l), "bgft_fake: content_id=%s tid=%s", content_id, title_id);
        log_line(l);
    }

    /* Determinar task_id: usar 0x00FFFFFF como ID fijo alto */
    static const unsigned int FAKE_TASK_ID = 0x00FFFFFF;
    char task_dir[64];
    snprintf(task_dir, sizeof(task_dir), "/user/bgft/task/%08x", FAKE_TASK_ID);

    mkdir("/user/bgft",          0755);
    mkdir("/user/bgft/task",     0755);
    mkdir(task_dir,              0755);

    /* Construir el pdb modificado */
    static uint8_t pdb_buf[PDB_SIZE];
    memcpy(pdb_buf, s_pdb_template, PDB_SIZE);

    /* Reemplazar content_id (offset 0x0dc, 36 bytes) */
    memcpy(pdb_buf + PDB_CID_OFF, content_id, 36);

    /* Reemplazar title_id (offset 0x10c, 9 bytes) — title_id siempre 9 chars */
    if (strlen(title_id) == 9)
        memcpy(pdb_buf + PDB_TID_OFF, title_id, 9);

    /* Reemplazar ruta de instalacion (offset 0x298, 27 bytes)
     * Formato: "/user/app/CUSAXXXXX/app.pkg" = exactamente 27 bytes */
    if (strlen(title_id) == 9) {
        char inst_path[28];
        snprintf(inst_path, sizeof(inst_path), "/user/app/%.9s/app.pkg", title_id);
        memcpy(pdb_buf + PDB_PATH_OFF, inst_path, 27);
    }

    /* Escribir d0.pdb y d1.pdb */
    char pdb_path[80];
    for (int i = 0; i < 2; i++) {
        snprintf(pdb_path, sizeof(pdb_path), "%s/d%d.pdb", task_dir, i);
        int fd = open(pdb_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            char l[80]; snprintf(l, sizeof(l), "bgft_fake: cannot write %s", pdb_path);
            log_line(l); return -1;
        }
        write(fd, pdb_buf, PDB_SIZE);
        close(fd);
    }

    {
        char l[96];
        snprintf(l, sizeof(l), "bgft_fake: task created at %s", task_dir);
        log_line(l);
    }
    return 0;
}

/* ────────────────────────────────────────────────────────────────────────────
 * BGFT — instala PKGs con task real, evita CE-32930-7
 * ──────────────────────────────────────────────────────────────────────── */
#define BGFT_OPT_DELETE_AFTER  0x00001
#define BGFT_OPT_NO_CDN_PARAM  0x10000
#pragma pack(push, 4)
struct bgft_dl_param {
    int user_id; int entitlement_type;
    const char *id, *content_url, *content_ex_url, *content_name;
    const char *icon_path, *sku_id;
    int option;
    const char *playgo_scenario_id, *release_date, *package_type, *package_sub_type;
    uint64_t package_size;
};
struct bgft_dl_param_ex { struct bgft_dl_param param; unsigned int slot; };
struct bgft_progress {
    unsigned int bits; int error_result;
    uint64_t length, transferred, length_total, transferred_total;
    unsigned int num_index, num_total, rest_sec, rest_sec_total;
    int preparing_percent, local_copy_percent;
};
struct bgft_init_p { void *mem; uint64_t size; };
#pragma pack(pop)
static int (*fn_bgft_init) (struct bgft_init_p *)             = NULL;
static int (*fn_bgft_reg)  (struct bgft_dl_param_ex *, int *) = NULL;
static int (*fn_bgft_start)(int)                              = NULL;
static int (*fn_bgft_prog) (int, struct bgft_progress *)      = NULL;
static int  g_bgft_loaded  = 0;
static char g_bgft_detail[128] = "not_loaded";

static int bgft_ensure(void) {
    if (g_bgft_loaded== 1) return 0;
    if (g_bgft_loaded==-1) return -1;

    /* Buscar libSceBgft ya cargado en el sistema */
    int h = -1;
    {
        int mods[256]; int mc = 0;
        getLoadedModules(mods, 256, &mc);
        for (int i = 0; i < mc && h < 0; i++) {
            struct moduleInfo mi; memset(&mi,0,sizeof(mi)); mi.size=sizeof(mi);
            if (getModuleInfo(mods[i],&mi)==0 && strstr(mi.name,"SceBgft"))
                h = mods[i];
        }
        if (h >= 0) { char l[64]; snprintf(l,sizeof(l),"bgft: found loaded h=%d",h); log_line(l); }
    }
    if (h < 0) {
        ps4_dynlib_load_prx("/system/common/lib/libSceBgft.sprx",0,&h,0);
        if(h<0){snprintf(g_bgft_detail,sizeof(g_bgft_detail),"dlopen h=%d",h);g_bgft_loaded=-1;return -1;}
        char lh[32]; snprintf(lh,sizeof(lh),"bgft: loaded h=%d",h); log_line(lh);
    }

    /* Probar nombres completos (FW 12.50 puede exportar por nombre) */
    static char a1[]="sceBgftInitialize";
    static char a2[]="sceBgftDownloadRegisterTaskByStorageEx";
    static char a3[]="sceBgftDownloadStartTask";
    static char a4[]="sceBgftDownloadGetProgress";
    getFunctionAddressByName(h,a1,&fn_bgft_init);
    getFunctionAddressByName(h,a2,&fn_bgft_reg);
    getFunctionAddressByName(h,a3,&fn_bgft_start);
    getFunctionAddressByName(h,a4,&fn_bgft_prog);
    { char l[128]; snprintf(l,sizeof(l),"bgft_name: init=%s reg=%s start=%s",
        fn_bgft_init?"ok":"NULL",fn_bgft_reg?"ok":"NULL",fn_bgft_start?"ok":"NULL"); log_line(l); }
    /* Variante sin Ex */
    if (!fn_bgft_reg) {
        static char a2b[]="sceBgftDownloadRegisterTaskByStorage";
        getFunctionAddressByName(h,a2b,&fn_bgft_reg);
        if (fn_bgft_reg) log_line("bgft: using RegisterTaskByStorage (no Ex)");
    }
    /* NIDs de flatz (FW 5.01) como ultimo recurso */
    if (!fn_bgft_init) { static char n1[]="BZ0olR8Da0g"; getFunctionAddressByName(h,n1,&fn_bgft_init); }
    if (!fn_bgft_reg)  { static char n2[]="nd+0DEOC68A"; getFunctionAddressByName(h,n2,&fn_bgft_reg);  }
    if (!fn_bgft_start){ static char n3[]="HRDHLMA9Y7s"; getFunctionAddressByName(h,n3,&fn_bgft_start);}
    if (!fn_bgft_prog) { static char n4[]="5txx+w0HYOs"; getFunctionAddressByName(h,n4,&fn_bgft_prog); }
    snprintf(g_bgft_detail,sizeof(g_bgft_detail),"h=%d init=%s reg=%s start=%s",h,
        fn_bgft_init?"ok":"NULL",fn_bgft_reg?"ok":"NULL",fn_bgft_start?"ok":"NULL");
    log_line(g_bgft_detail);
    if(!fn_bgft_init||!fn_bgft_reg||!fn_bgft_start){g_bgft_loaded=-1;return -2;}
    struct bgft_init_p ip; memset(&ip,0,sizeof(ip)); ip.mem=g_bgft_mem; ip.size=sizeof(g_bgft_mem);
    int r=fn_bgft_init(&ip);
    if(r!=0){snprintf(g_bgft_detail,sizeof(g_bgft_detail),"bgft_init 0x%08x",(uint32_t)r);
             log_line(g_bgft_detail);g_bgft_loaded=-1;return -3;}
    g_bgft_loaded=1; log_line("bgft_ensure: OK"); return 0;
}

static void bgft_install_pkg(int fd, const char *pkg_path, int dl_bytes) {
    if(bgft_ensure()!=0){
        char msg[256];
        snprintf(msg,sizeof(msg),
            "{\"status\":\"fail\",\"error\":\"bgft: %s\",\"bytes\":%d}",
            g_bgft_detail,dl_bytes);
        http_send(fd,500,msg); return;
    }
    const char *cn=strrchr(pkg_path,'/'); cn=cn?cn+1:pkg_path;
    char tid[20]={0};
    if(ai_ensure()==0&&fn_gettid){int ia=0;fn_gettid(pkg_path,tid,&ia);}
    struct bgft_dl_param_ex dp; memset(&dp,0,sizeof(dp));
    dp.param.entitlement_type=5; dp.param.id="";
    dp.param.content_url=pkg_path; dp.param.content_name=cn;
    dp.param.icon_path=""; dp.param.playgo_scenario_id="0";
    dp.param.option=BGFT_OPT_NO_CDN_PARAM|BGFT_OPT_DELETE_AFTER; dp.slot=0;
    int task_id=-1;
    int r=fn_bgft_reg(&dp,&task_id);
    {char l[128];snprintf(l,sizeof(l),"bgft_register ret=0x%08x task_id=%d",(uint32_t)r,task_id);log_line(l);}
    if(r!=0||task_id<0){
        char msg[128];
        snprintf(msg,sizeof(msg),
            "{\"status\":\"fail\",\"error\":\"bgft_reg 0x%08x\",\"bytes\":%d}",
            (uint32_t)r,dl_bytes);
        http_send(fd,500,msg); return;
    }
    r=fn_bgft_start(task_id);
    {char l[64];snprintf(l,sizeof(l),"bgft_start ret=0x%08x",(uint32_t)r);log_line(l);}
    if(r!=0){
        char msg[128];
        snprintf(msg,sizeof(msg),
            "{\"status\":\"fail\",\"error\":\"bgft_start 0x%08x\",\"bytes\":%d}",
            (uint32_t)r,dl_bytes);
        http_send(fd,500,msg); return;
    }
    strncpy(g_last_st,"bgft_installing",sizeof(g_last_st)-1);
    char resp[256];
    snprintf(resp,sizeof(resp),
        "{\"status\":\"success\",\"bytes\":%d,\"title_id\":\"%s\",\"task_id\":%d}",
        dl_bytes,tid,task_id);
    http_send(fd,200,resp);
    notify("PKGSender\nInstalando...\n(BGFT)");
    if(fn_bgft_prog){
        int last_ms=-1;
        for(int p=0;p<14400;p++){
            sceKernelUsleep(500000);
            struct bgft_progress prog; memset(&prog,0,sizeof(prog));
            if(fn_bgft_prog(task_id,&prog)!=0) break;
            if(prog.error_result!=0){char l[64];snprintf(l,sizeof(l),"bgft_error 0x%08x",(uint32_t)prog.error_result);log_line(l);break;}
            uint64_t tot=prog.length_total>0?prog.length_total:prog.length;
            uint64_t xf=prog.transferred_total>0?prog.transferred_total:prog.transferred;
            int pct=(tot>0)?(int)((xf*100ULL)/tot):prog.local_copy_percent;
            g_dl_pct=pct;
            int ms=(pct/25)*25;
            if(ms>0&&ms!=last_ms&&pct>=ms){last_ms=ms;char ntf[48];snprintf(ntf,sizeof(ntf),"PKGSender\nInstalando %d%%",pct);printf_notification("%s",ntf);}
            if(tot>0&&xf>=tot) break;
            if(prog.num_total>0&&prog.num_index>=prog.num_total) break;
        }
    }
    strncpy(g_last_st,"ok",sizeof(g_last_st)-1);
    log_line("bgft_done");
    notify("PKGSender\nInstalacion completada!");
}

/* ────────────────────────────────────────────────────────────────────────────
 * JSON helpers
 * ──────────────────────────────────────────────────────────────────────── */
static int json_str(const char *js, const char *key, char *out, int sz)
{
    if (!js||!key||!out||sz<=0) return -1;
    out[0]='\0';
    char needle[128]; snprintf(needle,sizeof(needle),"\"%s\"",key);
    char *p=strstr((char*)js,needle); if(!p) return -1;
    p+=strlen(needle);
    while(*p==' '||*p=='\t'||*p==':') p++;
    if(*p!='"') return -1;
    p++;
    int i=0;
    while(*p&&*p!='"'&&i<sz-1){
        if(*p=='\\'&&*(p+1)){
            p++;
            switch(*p){
                case '"': out[i++]='"'; break;
                case '\\':out[i++]='\\';break;
                case 'n': out[i++]='\n';break;
                case 'r': out[i++]='\r';break;
                case '/': out[i++]='/'; break;
                default:  out[i++]=*p;  break;
            }
        } else out[i++]=*p;
        p++;
    }
    out[i]='\0'; return i;
}

static int json_arr_first(const char *js, const char *key, char *out, int sz)
{
    if (!js||!key||!out||sz<=0) return -1;
    out[0]='\0';
    char needle[128]; snprintf(needle,sizeof(needle),"\"%s\"",key);
    char *p=strstr((char*)js,needle); if(!p) return -1;
    p+=strlen(needle);
    while(*p==' '||*p==':'||*p=='\t') p++;
    if(*p!='[') return -1;
    p++;
    while(*p==' '||*p=='\t'||*p=='\r'||*p=='\n') p++;
    if(*p!='"') return -1;
    p++;
    int i=0;
    while(*p&&*p!='"'&&i<sz-1){
        if(*p=='\\'&&*(p+1)=='/' ){out[i++]='/';p+=2;continue;}
        if(*p=='\\'&&*(p+1)=='"' ){out[i++]='"';p+=2;continue;}
        out[i++]=*p++;
    }
    out[i]='\0'; return i;
}

/* ────────────────────────────────────────────────────────────────────────────
 * URL decode — convierte %XX y + a caracteres reales
 * ──────────────────────────────────────────────────────────────────────── */
static void url_decode(const char *src, char *dst, int dsz)
{
    int o=0;
    while(*src && o<dsz-1){
        if(*src=='%' && src[1] && src[2]){
            char tmp[3]={src[1],src[2],0};
            int v=(int)strtol(tmp,NULL,16);
            if(v>0){dst[o++]=(char)v; src+=3; continue;}
        } else if(*src=='+'){dst[o++]=' '; src++; continue;}
        dst[o++]=*src++;
    }
    dst[o]='\0';
}

/* ────────────────────────────────────────────────────────────────────────────
 * dns_resolve — resolucion DNS con cliente UDP propio
 * ──────────────────────────────────────────────────────────────────────────
 * No usa sceNetResolverCreate/StartNtoa/Destroy (no disponibles en libPS4).
 * Construye una query DNS tipo A y la envia por UDP al servidor indicado.
 * Parsea la respuesta y devuelve la primera IPv4 encontrada.
 *
 * Parametros:
 *   host      — hostname a resolver (o IP literal, devuelve inmediatamente)
 *   dns_srv   — IP del servidor DNS en formato "x.x.x.x"
 *   out       — struct in_addr rellenado si retorna 0
 *
 * Retorna 0 si OK, -1 si fallo.
 * ──────────────────────────────────────────────────────────────────────── */
static int dns_resolve_via(const char *host, const char *dns_srv, struct in_addr *out)
{
    /* Intentar primero como IP literal — sin DNS */
    if (sceNetInetPton(AF_INET, host, out) == 1) return 0;

    /* ── Construir paquete DNS query (RFC 1035) ── */
    unsigned char q[512];
    memset(q, 0, sizeof(q));
    int qlen = 0;

    /* Header: ID=0x1234, FLAGS=0x0100 (RD=1), QDCOUNT=1 */
    q[qlen++]=0x12; q[qlen++]=0x34;
    q[qlen++]=0x01; q[qlen++]=0x00;
    q[qlen++]=0x00; q[qlen++]=0x01;  /* QDCOUNT */
    q[qlen++]=0x00; q[qlen++]=0x00;  /* ANCOUNT */
    q[qlen++]=0x00; q[qlen++]=0x00;  /* NSCOUNT */
    q[qlen++]=0x00; q[qlen++]=0x00;  /* ARCOUNT */

    /* QNAME: codificar hostname como secuencia de labels */
    const char *p = host;
    while (*p) {
        const char *dot = strchr(p, '.');
        int lablen = dot ? (int)(dot - p) : (int)strlen(p);
        if (lablen > 63 || qlen + lablen + 2 > (int)sizeof(q)) return -1;
        q[qlen++] = (unsigned char)lablen;
        memcpy(q + qlen, p, lablen);
        qlen += lablen;
        if (!dot) break;
        p = dot + 1;
    }
    q[qlen++] = 0;          /* etiqueta raiz */
    q[qlen++] = 0; q[qlen++] = 1;  /* QTYPE = A  */
    q[qlen++] = 0; q[qlen++] = 1;  /* QCLASS = IN */

    /* ── Socket UDP ──
     * NOTA: sceNetSendto / sceNetRecvfrom NO existen en libPS4.
     * Solución: sceNetConnect() en socket UDP fija el destino,
     * permitiendo usar sceNetSend() / sceNetRecv() normalmente.
     *
     * SCE_NET_SO_RCVTIMEO tampoco está definido en el header del SDK;
     * usamos el valor BSD raw 0x1006 directamente.
     */
    int sock = sceNetSocket("dns_q", AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    /* Timeout de recepcion: 3 segundos (valor FreeBSD/PS4 = 0x1006) */
    struct { int sec; int usec; } tv = {3, 0};
    sceNetSetsockopt(sock, SCE_NET_SOL_SOCKET, 0x1006, &tv, sizeof(tv));

    /* Conectar el socket UDP al servidor DNS — permite usar Send/Recv normales */
    struct sockaddr_in dns_addr;
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port   = sceNetHtons(53);
    sceNetInetPton(AF_INET, dns_srv, &dns_addr.sin_addr);

    if (sceNetConnect(sock, (struct sockaddr*)&dns_addr, sizeof(dns_addr)) < 0) {
        sceNetSocketClose(sock); return -1;
    }

    /* Enviar query DNS */
    int sent = sceNetSend(sock, q, qlen, 0);
    if (sent < 0) { sceNetSocketClose(sock); return -1; }

    /* Recibir respuesta */
    unsigned char r[512];
    int rlen = sceNetRecv(sock, r, sizeof(r), 0);
    sceNetSocketClose(sock);
    if (rlen < 12) return -1;

    /* Verificar: QR=1 (respuesta) y RCODE=0 (sin error) */
    if (!(r[2] & 0x80))       return -1;   /* no es respuesta */
    if ((r[3] & 0x0F) != 0)   return -1;   /* RCODE != 0 */

    int ancount = (r[6]<<8) | r[7];
    if (ancount == 0) return -1;

    /* Saltar seccion de pregunta: QNAME + QTYPE + QCLASS */
    int pos = 12;
    while (pos < rlen) {
        if ((r[pos] & 0xC0) == 0xC0) { pos += 2; break; }  /* puntero comprimido */
        if (r[pos] == 0)              { pos += 1; break; }  /* fin del nombre */
        pos += (int)r[pos] + 1;
    }
    pos += 4;  /* QTYPE (2) + QCLASS (2) */

    /* Leer registros de respuesta buscando tipo A (IPv4) */
    for (int i = 0; i < ancount; i++) {
        if (pos >= rlen) break;

        /* Saltar nombre del registro */
        if ((r[pos] & 0xC0) == 0xC0) {
            pos += 2;
        } else {
            while (pos < rlen && r[pos]) pos += (int)r[pos] + 1;
            if (pos < rlen) pos++;
        }

        if (pos + 10 > rlen) break;

        int rtype = (r[pos]<<8)   | r[pos+1];
        /* rclass  = (r[pos+2]<<8) | r[pos+3]; */
        /* ttl     = 4 bytes at pos+4 */
        int rdlen = (r[pos+8]<<8) | r[pos+9];
        pos += 10;

        if (rtype == 1 && rdlen == 4 && pos + 4 <= rlen) {
            /* Registro A encontrado */
            memcpy(&out->s_addr, r + pos, 4);
            return 0;
        }
        pos += rdlen;
    }
    return -1;
}

/*
 * dns_resolve — intenta primero con 8.8.8.8, luego con 1.1.1.1
 */
static int dns_resolve(const char *host, struct in_addr *out)
{
    if (dns_resolve_via(host, DNS_SERVER, out) == 0) return 0;
    return dns_resolve_via(host, DNS_ALT, out);
}

/* ────────────────────────────────────────────────────────────────────────────
 * parse_url — extrae host, path y puerto de una URL http://...
 * ──────────────────────────────────────────────────────────────────────── */
static int parse_url(const char *url, char *host, int hs,
                     char *path, int ps, int *port)
{
    *port = 80; host[0] = '\0'; path[0] = '\0';
    const char *p = url;
    if      (strncmp(p, "http://",  7) == 0) { p += 7; *port = 80;  }
    else if (strncmp(p, "https://", 8) == 0) { p += 8; *port = 443; }
    else return -1;

    const char *sl = strchr(p, '/');
    const char *co = strchr(p, ':');
    int he = sl ? (int)(sl - p) : (int)strlen(p);

    if (co && (!sl || co < sl)) {
        int hl = (int)(co - p); if (hl >= hs) hl = hs - 1;
        memcpy(host, p, hl); host[hl] = '\0';
        *port = atoi(co + 1);
    } else {
        if (he >= hs) he = hs - 1;
        memcpy(host, p, he); host[he] = '\0';
    }
    if (sl) { strncpy(path, sl, ps - 1); path[ps - 1] = '\0'; }
    else    { path[0] = '/'; path[1] = '\0'; }
    return 0;
}

/* ────────────────────────────────────────────────────────────────────────────
 * gsched + ffs_allocblocks — optimizacion de escritura en disco
 * ──────────────────────────────────────────────────────────────────────── */
static int gsched_set_prio(int pkg_fd)
{
    int gfd = open("/dev/gsched_is.ctl", O_RDONLY, 0);
    if (gfd < 0) return gfd;
    struct { void *data; uint32_t slot; uint32_t prio; } a;
    a.data = (void*)(uintptr_t)pkg_fd; a.slot = 1; a.prio = 0;
    int r = ioctl(gfd, 0xC0209406UL, &a);
    close(gfd);
    return r;
}

static int ffs_alloc(int pkg_fd, int64_t size)
{
    if (size <= 0) return -1;
    struct { uint64_t size, zero, flags, align; } a;
    a.size = (uint64_t)size; a.zero = 0; a.flags = 0x80; a.align = 0;
    return ioctl(pkg_fd, 0xC02066A1UL, &a);
}

/* path_encode — codifica caracteres no validos en HTTP request-target
 * RFC 7230: el path no puede tener espacios literales ni chars de control.
 * Codifica: espacio, [, ], {, }, |, ^, `, <, >, y chars no-ASCII.
 * Los % ya existentes se dejan tal cual (no doble-encode). */
static void path_encode(const char *src, char *dst, int dsz)
{
    static const char hex[] = "0123456789ABCDEF";
    int o = 0;
    while (*src && o < dsz - 4) {
        unsigned char c = (unsigned char)*src;
        /* Dejar % sin tocar (ya esta codificado) */
        if (c == '%') {
            dst[o++] = '%'; src++; continue;
        }
        /* Codificar: espacio y chars problematicos en HTTP paths */
        if (c == ' '  || c == '[' || c == ']' || c == '{' || c == '}' ||
            c == '|'  || c == '^' || c == '`' || c == '<' || c == '>' ||
            c == '"'  || c == '\\' || c <= 0x1F || c >= 0x7F) {
            dst[o++] = '%';
            dst[o++] = hex[(c >> 4) & 0xF];
            dst[o++] = hex[c & 0xF];
        } else {
            dst[o++] = (char)c;
        }
        src++;
    }
    dst[o] = '\0';
}

/* ────────────────────────────────────────────────────────────────────────────
 * http_get_small — descarga una respuesta HTTP pequeña (< 8KB) a buffer.
 * Usado para consultar APIs REST como archive.org/metadata.
 * Retorna longitud del body, o -1 si fallo.
 * ──────────────────────────────────────────────────────────────────────── */
static int http_get_small(const char *host, int port, const char *path,
                           char *out, int outsz)
{
    struct in_addr a4; memset(&a4, 0, sizeof(a4));
    if (dns_resolve(host, &a4) != 0) return -1;

    int sk = sceNetSocket("api_get", AF_INET, SOCK_STREAM, 0);
    if (sk < 0) return -1;

    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = sceNetHtons((uint16_t)port);
    sa.sin_addr   = a4;
    if (sceNetConnect(sk, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        sceNetSocketClose(sk); return -1;
    }

    char req[1024];
    int rl = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: PS4PKGSender/9\r\n"
        "Accept: application/json\r\nConnection: close\r\n\r\n",
        path, host);
    sceNetSend(sk, req, rl, 0);

    /* Leer respuesta completa */
    static char rbuf[8192];
    int total = 0;
    memset(rbuf, 0, sizeof(rbuf));
    while (total < (int)sizeof(rbuf) - 1) {
        int n = sceNetRecv(sk, rbuf + total, sizeof(rbuf) - 1 - total, 0);
        if (n <= 0) break;
        total += n;
    }
    sceNetSocketClose(sk);

    /* Saltar headers HTTP */
    char *body = strstr(rbuf, "\r\n\r\n");
    if (!body) return -1;
    body += 4;
    int blen = total - (int)(body - rbuf);
    if (blen <= 0 || blen >= outsz) return -1;
    memcpy(out, body, blen);
    out[blen] = '\0';
    return blen;
}

/* ────────────────────────────────────────────────────────────────────────────
 * archiveorg_resolve — usa el API de metadatos de archive.org (HTTP puro)
 * para saltarse el CDN dn*.ca.archive.org que fuerza HTTPS.
 *
 * URL de metadatos: http://archive.org/metadata/COLLECTION
 * Respuesta JSON: {"d1":"ia803104.us.archive.org","dir":"/0/items/COLLECTION",...}
 *
 * Construye: http://d1/dir/filename
 *
 * Los servidores ia*.us.archive.org sirven archivos por HTTP sin redireccion HTTPS.
 *
 * Retorna 0 si OK, -1 si fallo.
 * ──────────────────────────────────────────────────────────────────────── */
static int archiveorg_resolve(const char *url_encoded, char *out, int outsz)
{
    /* Decodificar la URL para trabajar con el path real */
    char url[URL_MAX];
    url_decode(url_encoded, url, sizeof(url));

    /* Extraer el path: /download/COLLECTION/FILE o /0/items/COLLECTION/FILE */
    const char *path_start = NULL;
    const char *prefixes[] = {
        "/download/", "/0/items/", NULL
    };
    for (int i = 0; prefixes[i]; i++) {
        path_start = strstr(url, prefixes[i]);
        if (path_start) { path_start += strlen(prefixes[i]); break; }
    }
    if (!path_start) return -1;

    /* Extraer nombre de la coleccion (hasta el primer /) */
    char collection[256] = {0};
    const char *slash = strchr(path_start, '/');
    if (!slash) return -1;
    int clen = (int)(slash - path_start);
    if (clen <= 0 || clen >= (int)sizeof(collection)) return -1;
    memcpy(collection, path_start, clen);
    collection[clen] = '\0';

    /* El nombre del fichero es lo que queda despues del / */
    const char *filename = slash + 1;
    if (!filename[0]) return -1;

    /* Consultar http://archive.org/metadata/COLLECTION */
    char meta_path[512];
    snprintf(meta_path, sizeof(meta_path), "/metadata/%s", collection);
    {
        char l[256];
        snprintf(l, sizeof(l), "archiveorg_resolve: querying metadata for '%s'", collection);
        log_line(l);
    }

    static char meta_json[8192];
    if (http_get_small("archive.org", 80, meta_path,
                        meta_json, sizeof(meta_json)) < 0) {
        log_line("archiveorg_resolve: metadata query failed");
        return -1;
    }

    /* Extraer "d1" — servidor de almacenamiento primario */
    char d1[128] = {0};
    if (json_str(meta_json, "d1", d1, sizeof(d1)) <= 0) {
        log_line("archiveorg_resolve: no d1 in metadata");
        return -1;
    }

    /* Extraer "dir" — directorio del item en el servidor */
    char dir[512] = {0};
    if (json_str(meta_json, "dir", dir, sizeof(dir)) <= 0) {
        /* Si no hay "dir", construir la ruta estandar */
        snprintf(dir, sizeof(dir), "/0/items/%s", collection);
    }

    /* Codificar el nombre del fichero para la URL */
    char enc_file[URL_MAX];
    path_encode(filename, enc_file, sizeof(enc_file));

    /* Construir URL final: http://d1/dir/filename */
    snprintf(out, outsz, "http://%s%s/%s", d1, dir, enc_file);

    {
        char l[256];
        snprintf(l, sizeof(l), "archiveorg_resolve: -> %.200s", out);
        log_line(l);
    }
    return 0;
}

/* is_archiveorg_url — detecta si una URL pertenece a archive.org o sus CDNs */
static int is_archiveorg_url(const char *url)
{
    return strstr(url, "archive.org") != NULL;
}

/* ────────────────────────────────────────────────────────────────────────────
 * download_pkg — descarga HTTP con soporte de:
 *   - Hostname (via dns_resolve)
 *   - Redirect 301/302/303/307 (archive.org los usa siempre)
 *   - URL decode automatico
 *
 * Codigos de retorno:
 *   0    OK
 *  -1    URL invalida / no es http://
 *  -2    no se pudo crear archivo temporal
 *  -3    error al crear socket de descarga
 *  -4    TCP connect fallido
 *  -5    servidor no devolvio 200/206
 *  -6    sin datos recibidos
 *  -100  redirect a HTTPS directo no soportado
 *  -101  DNS fallo — hostname no resuelto
 *  -102  bucle de redirects — mismo host redirige en loop (CDN fuerza HTTPS)
 * ──────────────────────────────────────────────────────────────────────── */
static int download_pkg(const char *url_raw, const char *dst, int64_t *out_bytes)
{
    /* Buffers estaticos — evita presion de pila */
    static char s_host[128];
    static char s_path[URL_MAX];
    static char s_req[URL_MAX + 256];
    static char s_hdr[4096];
    static char s_chunk[65536];

    /* Decodificar URL */
    char dec[URL_MAX];
    url_decode(url_raw, dec, sizeof(dec));

    int port = 80;
    if (parse_url(dec, s_host, sizeof(s_host), s_path, sizeof(s_path), &port) < 0)
        return -1;
    if (port == 443)
        return -100;  /* HTTPS directo no soportado sin SSL */

    /* Resolver host -> IPv4 */
    struct in_addr a4;
    memset(&a4, 0, sizeof(a4));
    if (dns_resolve(s_host, &a4) != 0)
        return -101;

    /* HEAD para obtener Content-Length (fallo silencioso) */
    int64_t pkg_size = -1;
    {
        int sk = sceNetSocket("hd", AF_INET, SOCK_STREAM, 0);
        if (sk >= 0) {
            struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_port   = sceNetHtons((uint16_t)port);
            sa.sin_addr   = a4;
            if (sceNetConnect(sk, (struct sockaddr*)&sa, sizeof(sa)) == 0) {
                int rl;
                if (strstr(s_host, "archive.org") != NULL)
                    rl = snprintf(s_req, sizeof(s_req),
                        "HEAD %s HTTP/1.0\r\nHost: %s\r\n"
                        "User-Agent: PS4PKGSender/9\r\n"
                        "Authorization: " ARCHIVEORG_S3_AUTH "\r\n"
                        "Connection: close\r\n\r\n",
                        s_path, s_host);
                else
                    rl = snprintf(s_req, sizeof(s_req),
                        "HEAD %s HTTP/1.0\r\nHost: %s\r\n"
                        "User-Agent: PS4PKGSender/9\r\nConnection: close\r\n\r\n",
                        s_path, s_host);
                sceNetSend(sk, s_req, rl, 0);
                int hn = 0;
                memset(s_hdr, 0, sizeof(s_hdr));
                while (hn < (int)sizeof(s_hdr) - 1) {
                    int n = sceNetRecv(sk, s_hdr + hn, 1, 0);
                    if (n <= 0) break;
                    hn++; s_hdr[hn] = '\0';
                    if (strstr(s_hdr, "\r\n\r\n")) {
                        /* Solo confiar en Content-Length si el HEAD devuelve 200 OK
                         * (no un redirect de 301/302, cuyo cuerpo son ~100-200 bytes) */
                        char *hsp = strchr(s_hdr, ' ');
                        int  hsc  = hsp ? atoi(hsp + 1) : 0;
                        if (hsc == 200) {
                            char *cl = strstr(s_hdr, "\r\nContent-Length:");
                            if (!cl) cl = strstr(s_hdr, "\r\ncontent-length:");
                            if (cl) pkg_size = (int64_t)atoi(cl + 17);
                        }
                        break;
                    }
                }
            }
            sceNetSocketClose(sk);
        }
    }

    /* Abrir archivo destino */
    int fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -2;
    ps4_ftruncate(fd, 0);
    g_gsched   = gsched_set_prio(fd);
    g_ffsalloc = ffs_alloc(fd, pkg_size);
    {
        char l[128];
        snprintf(l, sizeof(l), "prealloc size=%lld gsched=%d ffs=%d",
                 (long long)pkg_size, g_gsched, g_ffsalloc);
        log_line(l);
    }

    /* ── GET con soporte de redirect ──
     * archive.org hace: http://archive.org/... -> http://ia8009xx.us.archive.org/...
     * Seguimos hasta 5 redirecciones.
     */
    char  cur_host[128]; strncpy(cur_host, s_host, sizeof(cur_host) - 1);
    char  cur_path[URL_MAX];
    { char enc[URL_MAX]; path_encode(s_path, enc, sizeof(enc)); strncpy(cur_path, enc, sizeof(cur_path)-1); }
    int   cur_port   = port;
    struct in_addr cur_a4 = a4;

    int   redir_count = 0;
    int   sock        = -1;
    int64_t clen      = pkg_size;
    int   boff        = 0;

    /* Registro de hosts visitados para deteccion de loops */
    char  visited[6][128];
    int   visited_n = 0;
    int   https_redir_count = 0;  /* redirects HTTPS→HTTP en el mismo host */
    memset(visited, 0, sizeof(visited));

get_retry:
    /* Detectar loop HTTPS en ca.archive.org:
     * si el mismo host nos ha redirigido a HTTPS 2+ veces, ir a archiveorg_resolve */
    if (https_redir_count >= 2 && strstr(cur_host, "archive.org") != NULL) {
        if (sock >= 0) sceNetSocketClose(sock);
        close(fd);
        if (is_archiveorg_url(url_raw)) {
            char ia_url[URL_MAX] = {0};
            if (archiveorg_resolve(url_raw, ia_url, sizeof(ia_url)) == 0) {
                log_line("https_loop: retrying via archive.org ia server");
                if (out_bytes) *out_bytes = 0;
                return download_pkg(ia_url, dst, out_bytes);
            }
        }
        log_line("https_loop: no fallback available");
        return -102;
    }

    /* Detectar loop: si ya visitamos cur_host mas de 2 veces, es un loop */
    {
        int already = 0;
        for (int vi = 0; vi < visited_n; vi++) {
            if (strcmp(visited[vi], cur_host) == 0) already++;
        }
        if (already >= 2) {
            /* Loop detectado — si es archive.org, usar metadata API */
            if (sock >= 0) sceNetSocketClose(sock);
            close(fd);

            if (is_archiveorg_url(url_raw)) {
                char ia_url[URL_MAX] = {0};
                if (archiveorg_resolve(url_raw, ia_url, sizeof(ia_url)) == 0) {
                    log_line("loop detected: retrying via archive.org ia server");
                    if (out_bytes) *out_bytes = 0;
                    return download_pkg(ia_url, dst, out_bytes);
                }
            }
            log_line("loop detected: no fallback available");
            return -102;
        }
        /* Registrar host actual */
        if (visited_n < 6)
            strncpy(visited[visited_n++], cur_host, 127);
    }
    if (sock >= 0) sceNetSocketClose(sock);
    sock = sceNetSocket("dl", AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { close(fd); return -3; }

    {
        struct sockaddr_in sa2; memset(&sa2, 0, sizeof(sa2));
        sa2.sin_family = AF_INET;
        sa2.sin_port   = sceNetHtons((uint16_t)cur_port);
        sa2.sin_addr   = cur_a4;
        if (sceNetConnect(sock, (struct sockaddr*)&sa2, sizeof(sa2)) < 0) {
            sceNetSocketClose(sock); close(fd); return -4;
        }
    }

    {
        int rl;
        if (strstr(cur_host, "archive.org") != NULL)
            rl = snprintf(s_req, sizeof(s_req),
                "GET %s HTTP/1.0\r\nHost: %s\r\n"
                "User-Agent: PS4PKGSender/9\r\n"
                "Authorization: " ARCHIVEORG_S3_AUTH "\r\n"
                "Connection: close\r\n\r\n",
                cur_path, cur_host);
        else
            rl = snprintf(s_req, sizeof(s_req),
                "GET %s HTTP/1.0\r\nHost: %s\r\n"
                "User-Agent: PS4PKGSender/9\r\nConnection: close\r\n\r\n",
                cur_path, cur_host);
        sceNetSend(sock, s_req, rl, 0);
    }

    /* Leer headers HTTP de respuesta */
    {
        int hn = 0;
        memset(s_hdr, 0, sizeof(s_hdr));
        boff = 0;

        while (hn < (int)sizeof(s_hdr) - 1) {
            int n = sceNetRecv(sock, s_hdr + hn, 1, 0);
            if (n <= 0) break;
            hn++; s_hdr[hn] = '\0';

            char *end = strstr(s_hdr, "\r\n\r\n");
            if (!end) continue;
            boff = (int)(end - s_hdr) + 4;

            char *sp = strchr(s_hdr, ' ');
            int   sc = sp ? atoi(sp + 1) : 0;

            /* Redirect 301 / 302 / 303 / 307 */
            if ((sc == 301 || sc == 302 || sc == 303 || sc == 307)
                && redir_count < 5)
            {
                char *loc = strstr(s_hdr, "\r\nLocation:");
                if (!loc) loc = strstr(s_hdr, "\r\nlocation:");
                if (loc) {
                    loc += 11;
                    while (*loc == ' ') loc++;
                    char new_url[URL_MAX] = {0};
                    int  li = 0;
                    while (*loc && *loc != '\r' && *loc != '\n'
                           && li < (int)sizeof(new_url) - 1)
                        new_url[li++] = *loc++;
                    new_url[li] = '\0';

                    {
                        char l[256];
                        snprintf(l, sizeof(l), "redirect %d -> %.200s", sc, new_url);
                        log_line(l);
                    }

                    if (strncmp(new_url, "https://", 8) == 0) {
                        /* Redirect a HTTPS: intentar http:// equivalente */
                        char http_redir[URL_MAX];
                        snprintf(http_redir, sizeof(http_redir), "http://%s", new_url + 8);
                        strncpy(new_url, http_redir, sizeof(new_url) - 1);
                        log_line("redir https->http auto-convert");
                        https_redir_count++;
                    }

                    char  nh[128] = {0}, np[URL_MAX] = {0};
                    int   np2 = 80;
                    if (parse_url(new_url, nh, sizeof(nh),
                                  np, sizeof(np), &np2) == 0) {
                        struct in_addr na4; memset(&na4, 0, sizeof(na4));
                        if (dns_resolve(nh, &na4) == 0) {
                            strncpy(cur_host, nh, sizeof(cur_host) - 1);
                            /* Codificar espacios y chars especiales en el path del redirect */
                            char enc_path[URL_MAX];
                            path_encode(np, enc_path, sizeof(enc_path));
                            strncpy(cur_path, enc_path, sizeof(cur_path) - 1);
                            cur_port = np2;
                            cur_a4   = na4;
                            redir_count++;
                            goto get_retry;
                        }
                    }
                }
                /* No pudimos parsear el redirect — caemos al error -5 */
            }

            if (sc != 200 && sc != 206) {
                sceNetSocketClose(sock); close(fd); return -5;
            }

            char *cl = strstr(s_hdr, "\r\nContent-Length:");
            if (!cl) cl = strstr(s_hdr, "\r\ncontent-length:");
            if (cl) {
                clen = (int64_t)atoi(cl + 17);
                if (g_ffsalloc != 0 && clen > 0) {
                    g_ffsalloc = ffs_alloc(fd, clen);
                    char lffs[64];
                    snprintf(lffs,sizeof(lffs),"ffs_retry size=%lld ret=%d",(long long)clen,g_ffsalloc);
                    log_line(lffs);
                }
            }
            break;
        }
    }

    /* Escribir datos al archivo */
    int64_t written = 0;
    {
        /* Bytes que llegaron junto con los headers */
        int hn2 = (int)strlen(s_hdr);
        if (hn2 > boff) {
            write(fd, s_hdr + boff, hn2 - boff);
            written += hn2 - boff;
        }
    }
    { int last_ms=-1;
      while (1) {
        int want = sizeof(s_chunk);
        if (clen > 0) { int64_t rem=clen-written; if(rem<=0) break; if(rem<want) want=(int)rem; }
        int n = sceNetRecv(sock, s_chunk, want, 0);
        if (n <= 0) break;
        write(fd, s_chunk, n); written += n;
        g_dl_bytes_done=written; g_dl_bytes_total=clen;
        g_dl_pct=(clen>0)?(int)((written*100LL)/clen):0;
        if(clen>0){int ms=(g_dl_pct/25)*25;
            if(ms>0&&ms!=last_ms&&g_dl_pct>=ms){last_ms=ms;
                char ntf[64];snprintf(ntf,sizeof(ntf),"PKGSender %d%%\n%d/%d MB",
                    g_dl_pct,(int)(written/1048576LL),(int)(clen/1048576LL));
                printf_notification("%s",ntf);}}
      }
      g_dl_pct=100;
    }

    close(fd);
    sceNetSocketClose(sock);
    if (out_bytes) *out_bytes = written;
    return (written > 0) ? 0 : -6;
}

/* ────────────────────────────────────────────────────────────────────────────
 * run_install — instala el .pkg con AppInstUtil
 * ──────────────────────────────────────────────────────────────────────── */
static void run_install(int fd, const char *pkg_path, int dl_bytes)
{
    if (ai_ensure() != 0) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "{\"status\":\"fail\",\"error\":\"AppInstUtil: %s\",\"bytes\":%d}",
            g_ai_detail, dl_bytes);
        http_send(fd, 500, msg);
        return;
    }

    strncpy(g_last_st, "installing", sizeof(g_last_st) - 1);
    notify("PKGSender\nInstalando...");

    char tid[20] = {0}; int is_app = 0;
    if (fn_gettid) fn_gettid(pkg_path, tid, &is_app);
    if (is_app && fn_prepare) fn_prepare(pkg_path);

    /* Crear task BGFT en disco ANTES de instalar — así sceBgftNotifyGameWillStart
     * encontrará el task al intentar lanzar el juego */
    if (tid[0]) bgft_create_fake_task(pkg_path, tid);

    int r = fn_install(pkg_path, 0);
    g_last_inst = r;
    {
        char l[128];
        snprintf(l, sizeof(l), "install ret=0x%08x title=%s bytes=%d",
                 (uint32_t)r, tid, dl_bytes);
        log_line(l);
    }

    if (r == 0) {
        strncpy(g_last_st, "ok", sizeof(g_last_st) - 1);
        char resp[192];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"success\",\"bytes\":%d,\"title_id\":\"%s\"}", dl_bytes, tid);
        http_send(fd, 200, resp);
        notify("PKGSender\nInstalacion completada!");
        if (strncmp(pkg_path, TMP_PKG, sizeof(TMP_PKG)-1) == 0)
            unlink(pkg_path);
    } else {
        strncpy(g_last_st, "error", sizeof(g_last_st) - 1);
        char msg[192];
        snprintf(msg, sizeof(msg),
            "{\"status\":\"fail\",\"error\":\"appinst 0x%08x\",\"bytes\":%d}",
            (uint32_t)r, dl_bytes);
        http_send(fd, 500, msg);
        char ntf[96];
        snprintf(ntf, sizeof(ntf), "PKGSender ERROR\nappinst 0x%08x", (uint32_t)r);
        notify(ntf);
    }
}

/* ────────────────────────────────────────────────────────────────────────────
 * do_install — descarga URL + instala con AppInstUtil
 *
 * Soporta:
 *   http://IP/...        descarga directa
 *   http://hostname/...  descarga con DNS
 *   https://...          rechazado (sin SSL) — la app Android usa proxy
 * ──────────────────────────────────────────────────────────────────────── */
static void do_install(int fd, const char *url_raw)
{
    /* Decode y validacion basica */
    char url[URL_MAX];
    memset(url, 0, sizeof(url));
    url_decode(url_raw, url, sizeof(url));

    if (!url[0]) {
        http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"URL vacia\"}");
        return;
    }

    /* HTTPS -> HTTP: archive.org y la mayoria de CDNs sirven en HTTP puro.
     * La cadena de redirects HTTP lleva siempre a la URL final del CDN.
     * No se necesita SSL en el payload. */
    if (strncmp(url, "https://", 8) == 0) {
        char http_url[URL_MAX];
        snprintf(http_url, sizeof(http_url), "http://%s", url + 8);
        strncpy(url, http_url, sizeof(url) - 1);
        log_line("https->http auto-convert");
    }

    if (strncmp(url, "http://", 7) != 0) {
        http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"URL invalida\"}");
        return;
    }

    strncpy(g_last_url, url, sizeof(g_last_url) - 1);
    strncpy(g_last_st, "downloading", sizeof(g_last_st) - 1);
    notify("PKGSender v9.24\nDescargando...");
    {
        const char *fn=strrchr(url,'/'); fn=fn?fn+1:url;
        url_decode(fn,g_dl_name,sizeof(g_dl_name));
        {char *q=strchr(g_dl_name,'?');if(q)*q='\0';}
        g_dl_bytes_done=0; g_dl_bytes_total=0; g_dl_pct=0;
        char l[URL_MAX + 32];
        snprintf(l, sizeof(l), "download_start url=%.4000s", url);
        log_line(l);
    }

    int64_t bytes = 0;
    int dr = download_pkg(url, TMP_PKG, &bytes);
    g_last_bytes = (int)bytes;

    if (dr != 0) {
        strncpy(g_last_st, "dl_error", sizeof(g_last_st) - 1);
        const char *reason =
            dr == -1   ? "URL invalida / no es http" :
            dr == -2   ? "no se pudo crear archivo temporal en /user/data" :
            dr == -3   ? "error al crear socket TCP" :
            dr == -4   ? "TCP connect fallido" :
            dr == -5   ? "servidor no devolvio 200/206" :
            dr == -6   ? "sin datos recibidos (archivo vacio?)" :
            dr == -100 ? "redirect a HTTPS sin SSL — el CDN no sirve en HTTP" :
            dr == -101 ? "DNS fallo — hostname no resuelto (8.8.8.8 / 1.1.1.1)" :
            dr == -102 ? "bucle de redirects HTTPS — servidor solo sirve SSL" :
                         "error de red desconocido";
        char msg[256];
        snprintf(msg, sizeof(msg),
            "{\"status\":\"fail\","
            "\"error\":\"descarga fallida: %s\","
            "\"code\":%d,\"bytes\":%d}",
            reason, dr, (int)bytes);
        log_line(msg);
        http_send(fd, 500, msg);
        char ntf[128];
        snprintf(ntf, sizeof(ntf), "PKGSender ERROR\n%.80s", reason);
        notify(ntf);
        return;
    }

    {
        char l[64];
        snprintf(l, sizeof(l), "download_ok bytes=%d", (int)bytes);
        log_line(l);
    }
    run_install(fd, TMP_PKG, (int)bytes);
}

/* ────────────────────────────────────────────────────────────────────────────
 * do_install_local — instala directamente desde ruta del sistema de archivos
 * ──────────────────────────────────────────────────────────────────────── */
static void do_install_local(int fd, const char *path)
{
    if (!path || !path[0]) {
        http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"path vacio\"}");
        return;
    }
    strncpy(g_last_url, path, sizeof(g_last_url) - 1);
    run_install(fd, path, 0);
}

/* ────────────────────────────────────────────────────────────────────────────
 * handle_client — dispatcher HTTP (un hilo por conexion, single-threaded)
 * ──────────────────────────────────────────────────────────────────────── */
static void handle_client(int fd)
{
    char buf[BUF_MAX];
    memset(buf, 0, sizeof(buf));

    /* Leer request completo (headers + body) */
    int total = 0;
    while (total < (int)sizeof(buf) - 1) {
        int n = sceNetRecv(fd, buf + total, sizeof(buf) - 1 - total, 0);
        if (n <= 0) break;
        total += n; buf[total] = '\0';

        char *he = strstr(buf, "\r\n\r\n");
        if (!he) continue;
        int bstart = (int)(he - buf) + 4;

        char *cl = strstr(buf, "\r\nContent-Length:");
        if (!cl) cl = strstr(buf, "\r\ncontent-length:");
        if (cl) {
            int clen = atoi(cl + 17);
            int have = total - bstart;
            while (have < clen && total < (int)sizeof(buf) - 1) {
                n = sceNetRecv(fd, buf + total, sizeof(buf) - 1 - total, 0);
                if (n <= 0) break;
                total += n; have += n; buf[total] = '\0';
            }
        }
        break;
    }
    if (total <= 0) { sceNetSocketClose(fd); return; }

    /* ── Rutas GET ── */

    if (strncmp(buf, "OPTIONS", 7) == 0) {
        http_send(fd, 204, ""); sceNetSocketClose(fd); return;
    }

    if (strncmp(buf, "GET /ping", 9) == 0 || strncmp(buf, "GET / ", 6) == 0) {
        /* "service":"ps4-pkgsender" es necesario para que la app Android
         * detecte este payload en lugar del Remote PKG Installer de flatz */
        http_send(fd, 200,
            "{\"status\":\"success\","
            "\"service\":\"ps4-pkgsender\","
            "\"version\":\"9.24\","
            "\"port\":12800,"
            "\"engine\":\"appinstutil\"}");
        sceNetSocketClose(fd); return;
    }

    if (strncmp(buf, "GET /shutdown", 13) == 0) {
        http_send(fd, 200, "{\"status\":\"success\",\"message\":\"detenido\"}");
        sceNetSocketClose(fd);
        notify("PKGSender\nDetenido — puerto 12800 libre");
        g_shutdown = 1;
        if (g_srv_fd >= 0) sceNetSocketClose(g_srv_fd);
        return;
    }

    if (strncmp(buf, "GET /api/status", 15) == 0 ||
        strncmp(buf, "GET /status",     11) == 0) {
        char resp[192];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"success\","
            "\"state\":\"%s\","
            "\"last_ret\":\"0x%08x\","
            "\"last_bytes\":%d}",
            g_last_st, (uint32_t)g_last_inst, g_last_bytes);
        http_send(fd, 200, resp); sceNetSocketClose(fd); return;
    }

    if (strncmp(buf, "GET /api/debug", 14) == 0) {
        ai_ensure();
        char resp[512];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"success\","
            "\"version\":\"9.24\","
            "\"firmware\":\"%s\","
            "\"firmware_raw\":\"0x%08x\","
            "\"appinst\":%s,"
            "\"appinst_detail\":\"%s\","
            "\"last_ret\":\"0x%08x\","
            "\"last_bytes\":%d,"
            "\"gsched\":%d,\"ffsalloc\":%d,"
            "\"state\":\"%s\","
            "\"last_url\":\"%s\"}",
            g_fw, g_fw_raw,
            g_ai_loaded == 1 ? "true" : "false", g_ai_detail,
            (uint32_t)g_last_inst, g_last_bytes,
            g_gsched, g_ffsalloc,
            g_last_st, g_last_url);
        http_send(fd, 200, resp); sceNetSocketClose(fd); return;
    }

    if (strncmp(buf, "GET /api/progress", 17) == 0) {
        char resp[256];
        snprintf(resp,sizeof(resp),
            "{\"status\":\"success\","
            "\"state\":\"%s\","
            "\"pct\":%d,"
            "\"bytes_done\":%lld,"
            "\"bytes_total\":%lld,"
            "\"name\":\"%s\"}",
            g_last_st,g_dl_pct,(long long)g_dl_bytes_done,(long long)g_dl_bytes_total,g_dl_name);
        http_send(fd,200,resp); sceNetSocketClose(fd); return;
    }

    if (strstr(buf, "/api/get_task_progress") != NULL) {
        char resp[128];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"success\","
            "\"result\":%d,"
            "\"length\":0,"
            "\"transferred_length\":%d}",
            g_last_inst == 0 ? 0 : -1, g_last_bytes);
        http_send(fd, 200, resp); sceNetSocketClose(fd); return;
    }

    if (strncmp(buf, "POST /api/is_exists", 19) == 0) {
        http_send(fd, 200,
            "{\"status\":\"success\",\"exists\":false,\"size\":0}");
        sceNetSocketClose(fd); return;
    }

    /* ── Extraer body ── */
    char *body = strstr(buf, "\r\n\r\n");
    if (body) body += 4;
    else { body = strstr(buf, "\n\n"); if (body) body += 2; }
    if (!body) body = (char*)"";

    /* ── Rutas POST ── */

    /* POST /install_url  — body = URL en texto plano (sin JSON) */
    if (strncmp(buf, "POST /install_url", 17) == 0) {
        if (!*body) {
            http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"Body vacio\"}");
            sceNetSocketClose(fd); return;
        }
        /* Limpiar posibles \r\n al final del body */
        int blen = (int)strlen(body);
        while (blen > 0 && (body[blen-1]=='\r'||body[blen-1]=='\n'||body[blen-1]==' '))
            body[--blen] = '\0';
        do_install(fd, body);
        sceNetSocketClose(fd); return;
    }

    /* POST /api/install  — {"type":"direct","packages":["URL"]}
     * Formato del Remote PKG Installer de flatz — compatibilidad total */
    if (strncmp(buf, "POST /api/install", 17) == 0) {
        if (!*body) {
            http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"Body vacio\"}");
            sceNetSocketClose(fd); return;
        }
        char url[URL_MAX] = {0};
        if (json_arr_first(body, "packages", url, sizeof(url)) <= 0)
            json_str(body, "url", url, sizeof(url));
        if (!url[0]) {
            http_send(fd, 400,
                "{\"status\":\"fail\",\"error\":\"Sin URL en packages[] ni en url\"}");
            sceNetSocketClose(fd); return;
        }
        do_install(fd, url);
        sceNetSocketClose(fd); return;
    }

    /* POST /install  — {"url":"URL"}  (formato legacy) */
    if (strncmp(buf, "POST /install", 13) == 0) {
        if (!*body) {
            http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"Body vacio\"}");
            sceNetSocketClose(fd); return;
        }
        char url[URL_MAX] = {0};
        if (json_str(body, "url", url, sizeof(url)) <= 0)
            json_str(body, "pkg_url", url, sizeof(url));
        if (!url[0]) {
            http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"Campo url requerido\"}");
            sceNetSocketClose(fd); return;
        }
        do_install(fd, url);
        sceNetSocketClose(fd); return;
    }

    /* POST /api/install_local  — instalar desde ruta local */
    if (strncmp(buf, "POST /api/install_local", 23) == 0) {
        if (!*body) {
            http_send(fd, 400, "{\"status\":\"fail\",\"error\":\"Body vacio\"}");
            sceNetSocketClose(fd); return;
        }
        char path[512] = {0};
        if (json_str(body, "path", path, sizeof(path)) <= 0)
            strncpy(path, body, sizeof(path) - 1);
        do_install_local(fd, path);
        sceNetSocketClose(fd); return;
    }

    /* Ruta no reconocida */
    http_send(fd, 404,
        "{\"status\":\"fail\","
        "\"error\":\"Endpoints disponibles: "
        "POST /install_url | POST /api/install | POST /install | "
        "POST /api/install_local | GET /ping | GET /api/debug | "
        "GET /api/status | GET /shutdown\"}");
    sceNetSocketClose(fd);
}

/* ────────────────────────────────────────────────────────────────────────────
 * port_free_previous — cierra instancia anterior en puerto 12800
 * ──────────────────────────────────────────────────────────────────────── */
static void port_free_previous(void)
{
    struct in_addr lo; memset(&lo, 0, sizeof(lo));
    sceNetInetPton(AF_INET, "127.0.0.1", &lo);

    int sk = sceNetSocket("kill_prev", AF_INET, SOCK_STREAM, 0);
    if (sk < 0) return;

    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = sceNetHtons(12800);
    sa.sin_addr   = lo;

    if (sceNetConnect(sk, (struct sockaddr*)&sa, sizeof(sa)) == 0) {
        static const char req[] =
            "GET /shutdown HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        sceNetSend(sk, (void*)req, sizeof(req) - 1, 0);
        char tmp[64]; while (sceNetRecv(sk, tmp, sizeof(tmp), 0) > 0) {}
        log_line("port_freed: shutdown sent to previous instance");
        sceKernelUsleep(500000);
    }
    sceNetSocketClose(sk);
}

/* ────────────────────────────────────────────────────────────────────────────
 * _main — entry point del payload
 * ──────────────────────────────────────────────────────────────────────── */
int _main(void)
{
    initKernel();
    initLibc();
    initNetwork();
    initSysUtil();
    initModule();

    /* Detectar firmware */
    {
        SceFwInfo i; memset(&i, 0, sizeof(i));
        if (sceKernelGetSystemSwVersion && sceKernelGetSystemSwVersion(&i) == 0) {
            g_fw_raw = i.version;
            if (i.version_string[0])
                strncpy(g_fw, i.version_string, sizeof(g_fw) - 1);
        }
    }

    int jb = jailbreak();
    {
        char l[96];
        snprintf(l, sizeof(l), "boot v9.24 fw=%s jb=0x%08x", g_fw, (uint32_t)jb);
        log_line(l);
    }

    notify("PKGSender v9.24\nArrancando...");

    /* Liberar puerto si hay una instancia anterior */
    port_free_previous();

    /* Crear socket servidor */
    int srv = sceNetSocket("pkgsender_srv", AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { notify("PKGSender ERROR\nsocket fallo"); return 1; }

    int opt = 1;
    sceNetSetsockopt(srv, SCE_NET_SOL_SOCKET, SCE_NET_SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = sceNetHtons(12800);
    addr.sin_addr.s_addr = IN_ADDR_ANY;

    if (sceNetBind(srv, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
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
    log_line("server_active port=12800");
    notify("PKGSender v9.24 ACTIVO\n:12800 listo\nDNS: 8.8.8.8 + 1.1.1.1");

    /* Bucle principal */
    for (;;) {
        struct sockaddr_in ca; unsigned int cl = sizeof(ca);
        int cfd = sceNetAccept(srv, (struct sockaddr*)&ca, &cl);
        if (cfd < 0) { if (g_shutdown) break; continue; }
        handle_client(cfd);
        if (g_shutdown) break;
    }

    notify("PKGSender\nPuerto 12800 liberado");
    return 0;
}