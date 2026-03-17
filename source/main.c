/*
 * ps4-pkgsender-payload v8.3
 * Base: v5 (funcionó) + AppInstUtil + descarga HTTP
 *
 * El v5 funcionó con BGFT pero BGFT rechaza payloads externos (0x80990002).
 * Esta versión mantiene EXACTAMENTE la misma estructura del v5 y reemplaza
 * solo el engine de instalación: descarga HTTP + sceAppInstUtilAppInstallPkg.
 *
 * Cambios respecto a v5:
 *   - Sin BGFT
 *   - Añade descarga HTTP a /user/data/pkgsender_tmp.pkg (solo IPs literales)
 *   - Añade sceAppInstUtilAppInstallPkg via ps4_dynlib_load_prx (syscall 594)
 *   - Añade gsched_set_slot_prio + ffs_allocblocks para bloques contiguos
 *   - Añade detect_firmware + log a /data/pkgsender.log
 *   - Añade /install_url, /api/install_local, /api/debug, /shutdown
 *   - buf[16384] como en v5 (no 65536)
 *   - url[2048] como en v5
 *   - Al arrancar: cierra socket previo en 12800 con SO_REUSEADDR
 */

#include <ps4.h>

/* ── Constantes ─────────────────────────────────────────────────────────── */
#define TMP_PKG  "/user/data/pkgsender_tmp.pkg"
#define LOG_PATH "/data/pkgsender.log"

/* ── Syscall 594: dynlib_load_prx ───────────────────────────────────────── */
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

/* ── Syscall 480: ftruncate ─────────────────────────────────────────────── */
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

/* ── AppInstUtil ─────────────────────────────────────────────────────────── */
static int (*fn_init)   (void)                                     = NULL;
static int (*fn_install)(const char *path, int r)                  = NULL;
static int (*fn_gettid) (const char *path, char *tid, int *is_app) = NULL;
static int (*fn_prepare)(const char *path)                         = NULL;

static int   g_ai_loaded = 0;
static char  g_ai_detail[128] = "not_loaded";

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

/* ── Estado global ───────────────────────────────────────────────────────── */
static char     g_fw[64]       = "unknown";
static uint32_t g_fw_raw       = 0;
static int      g_last_inst    = 0;
static int      g_last_bytes   = 0;
static char     g_last_url[256]= {0};
static char     g_last_st[32]  = "idle";
static int      g_gsched       = -999;
static int      g_ffsalloc     = -999;
static int      g_srv_fd       = -1;
static int      g_shutdown     = 0;

/* ── Log ─────────────────────────────────────────────────────────────────── */
static void log_line(const char *s)
{
    FILE *f = fopen(LOG_PATH, "a");
    if (!f) return;
    fprintf(f, "%s\n", s ? s : "");
    fclose(f);
}

/* ── HTTP helpers (igual que v5) ─────────────────────────────────────────── */
static const char CORS[] =
    "Access-Control-Allow-Origin: *\r\n"
    "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
    "Access-Control-Allow-Headers: Content-Type\r\n";

static void notify(const char *msg) { printf_notification("%s", msg); }

static void http_send(int fd, int code, const char *body)
{
    const char *st = code==200?"OK":code==204?"No Content":
                     code==400?"Bad Request":code==404?"Not Found":
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

/* ── JSON helpers (igual que v5) ─────────────────────────────────────────── */
static int json_str(const char *js, const char *key, char *out, int sz)
{
    if (!js||!key||!out||sz<=0) return -1;
    out[0]='\0';
    char needle[128]; snprintf(needle,sizeof(needle),"\"%s\"",key);
    char *p=strstr((char*)js,needle); if(!p) return -1;
    p+=strlen(needle);
    while(*p==' '||*p=='\t'||*p==':') p++;
    if(*p!='"') return -1; p++;
    int i=0;
    while(*p&&*p!='"'&&i<sz-1){
        if(*p=='\\'&&*(p+1)){p++;switch(*p){case'"':out[i++]='"';break;case'\\':out[i++]='\\';break;case'n':out[i++]='\n';break;case'r':out[i++]='\r';break;case'/':out[i++]='/';break;default:out[i++]=*p;break;}}
        else out[i++]=*p;p++;}
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
    if(*p!='[') return -1; p++;
    while(*p==' '||*p=='\t'||*p=='\r'||*p=='\n') p++;
    if(*p!='"') return -1; p++;
    int i=0;
    while(*p&&*p!='"'&&i<sz-1){
        if(*p=='\\'&&*(p+1)=='/')  {out[i++]='/';p+=2;continue;}
        if(*p=='\\'&&*(p+1)=='"')  {out[i++]='"';p+=2;continue;}
        out[i++]=*p++;}
    out[i]='\0'; return i;
}

/* ── URL decode (igual que v5) ───────────────────────────────────────────── */
static void url_decode(const char *src, char *dst, int dsz)
{
    int o=0;
    while(*src&&o<dsz-1){
        if(*src=='%'&&src[1]&&src[2]){
            char tmp[3]={src[1],src[2],0};
            int v=(int)strtol(tmp,NULL,16);
            if(v>0){dst[o++]=(char)v;src+=3;continue;}
        } else if(*src=='+'){dst[o++]=' ';src++;continue;}
        dst[o++]=*src++;
    }
    dst[o]='\0';
}

/* ── parse_url ───────────────────────────────────────────────────────────── */
static int parse_url(const char *url, char *host, int hs,
                     char *path, int ps, int *port)
{
    *port=80; host[0]='\0'; path[0]='\0';
    const char *p=url;
    if     (strncmp(p,"http://", 7)==0){p+=7;*port=80;}
    else if(strncmp(p,"https://",8)==0){p+=8;*port=443;}
    else return -1;
    const char *sl=strchr(p,'/'), *co=strchr(p,':');
    int he=sl?(int)(sl-p):(int)strlen(p);
    if(co&&(!sl||co<sl)){
        int hl=(int)(co-p); if(hl>=hs)hl=hs-1;
        memcpy(host,p,hl); host[hl]='\0'; *port=atoi(co+1);
    } else {
        if(he>=hs)he=hs-1; memcpy(host,p,he); host[he]='\0';
    }
    if(sl){strncpy(path,sl,ps-1);path[ps-1]='\0';}
    else{path[0]='/';path[1]='\0';}
    return 0;
}

/* ── gsched + ffs_allocblocks ────────────────────────────────────────────── */
static int gsched_set_prio(int pkg_fd)
{
    int gfd=open("/dev/gsched_is.ctl",O_RDONLY,0); if(gfd<0) return gfd;
    struct{void*data;uint32_t slot;uint32_t prio;} a;
    a.data=(void*)(uintptr_t)pkg_fd; a.slot=1; a.prio=0;
    int r=ioctl(gfd,0xC0209406UL,&a); close(gfd); return r;
}

static int ffs_alloc(int pkg_fd, int64_t size)
{
    if(size<=0) return -1;
    struct{uint64_t size,zero,flags,align;} a;
    a.size=(uint64_t)size; a.zero=0; a.flags=0x80; a.align=0;
    return ioctl(pkg_fd,0xC02066A1UL,&a);
}

/* ── Descarga HTTP → archivo local ──────────────────────────────────────── */
static int download_pkg(const char *url, const char *dst, int64_t *out_bytes)
{
    /* Buffers estáticos — sin presión de stack */
    static char host[64];
    static char path[2048];
    static char req[2560];
    static char hdr[2048];
    int port=80;

    char dec[2048]; url_decode(url,dec,sizeof(dec));
    if(parse_url(dec,host,sizeof(host),path,sizeof(path),&port)<0) return -1;
    if(port==443) return -100;

    struct in_addr a4; memset(&a4,0,sizeof(a4));
    if(sceNetInetPton(AF_INET,host,&a4)!=1) return -101;

    /* HEAD para Content-Length */
    int64_t pkg_size=-1;
    {
        int sk=sceNetSocket("hd",AF_INET,SOCK_STREAM,0); if(sk<0) goto skip_head;
        struct sockaddr_in sa; memset(&sa,0,sizeof(sa));
        sa.sin_family=AF_INET; sa.sin_port=sceNetHtons((uint16_t)port); sa.sin_addr=a4;
        if(sceNetConnect(sk,(struct sockaddr*)&sa,sizeof(sa))<0){sceNetSocketClose(sk);goto skip_head;}
        int rl=snprintf(req,sizeof(req),"HEAD %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: PS4/8.3\r\nConnection: close\r\n\r\n",path,host);
        sceNetSend(sk,req,rl,0);
        int hn=0;
        while(hn<(int)sizeof(hdr)-1){
            int n=sceNetRecv(sk,hdr+hn,1,0); if(n<=0)break;
            hn++;hdr[hn]='\0';
            if(strstr(hdr,"\r\n\r\n")){
                char*cl=strstr(hdr,"\r\nContent-Length:"); if(!cl)cl=strstr(hdr,"\r\ncontent-length:");
                if(cl)pkg_size=(int64_t)atoi(cl+17); break;
            }
        }
        sceNetSocketClose(sk);
    }
skip_head:;

    /* Abrir fichero y pre-alocar bloques contiguos */
    int fd=open(dst,O_WRONLY|O_CREAT|O_TRUNC,0644); if(fd<0) return -2;
    ps4_ftruncate(fd,0);
    g_gsched  = gsched_set_prio(fd);
    g_ffsalloc= ffs_alloc(fd,pkg_size);
    {char l[128]; snprintf(l,sizeof(l),"prealloc size=%lld gsched=%d ffs=%d",(long long)pkg_size,g_gsched,g_ffsalloc); log_line(l);}

    /* GET */
    int sock=sceNetSocket("dl",AF_INET,SOCK_STREAM,0); if(sock<0){close(fd);return -3;}
    struct sockaddr_in sa; memset(&sa,0,sizeof(sa));
    sa.sin_family=AF_INET; sa.sin_port=sceNetHtons((uint16_t)port); sa.sin_addr=a4;
    if(sceNetConnect(sock,(struct sockaddr*)&sa,sizeof(sa))<0){sceNetSocketClose(sock);close(fd);return -4;}
    int rl=snprintf(req,sizeof(req),"GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: PS4/8.3\r\nConnection: close\r\n\r\n",path,host);
    sceNetSend(sock,req,rl,0);

    /* Leer headers */
    int hn=0, boff=0; int64_t clen=pkg_size;
    memset(hdr,0,sizeof(hdr));
    while(hn<(int)sizeof(hdr)-1){
        int n=sceNetRecv(sock,hdr+hn,1,0); if(n<=0)break;
        hn++;hdr[hn]='\0';
        char*end=strstr(hdr,"\r\n\r\n"); if(!end)continue;
        boff=(int)(end-hdr)+4;
        char*sp=strchr(hdr,' '); if(!sp||atoi(sp+1)!=200){sceNetSocketClose(sock);close(fd);return -5;}
        char*cl=strstr(hdr,"\r\nContent-Length:"); if(!cl)cl=strstr(hdr,"\r\ncontent-length:");
        if(cl)clen=(int64_t)atoi(cl+17);
        break;
    }

    /* Escribir datos — chunk estático de 32KB */
    static char chunk[32768];
    int64_t written=0;
    if(hn>boff){write(fd,hdr+boff,hn-boff);written+=hn-boff;}
    while(1){
        int want=sizeof(chunk);
        if(clen>0){int64_t rem=clen-written;if(rem<=0)break;if(rem<want)want=(int)rem;}
        int n=sceNetRecv(sock,chunk,want,0); if(n<=0)break;
        write(fd,chunk,n); written+=n;
    }
    close(fd); sceNetSocketClose(sock);
    if(out_bytes)*out_bytes=written;
    return written>0?0:-6;
}

/* ── Instalar PKG con AppInstUtil ────────────────────────────────────────── */
static void run_install(int fd, const char *pkg_path, int dl_bytes)
{
    if(ai_ensure()!=0){
        char msg[256]; snprintf(msg,sizeof(msg),
            "{\"status\":\"fail\",\"error\":\"AppInstUtil fallo\",\"detail\":\"%s\"}",g_ai_detail);
        http_send(fd,500,msg); return;
    }
    strncpy(g_last_st,"installing",sizeof(g_last_st)-1);
    notify("PKGSender v8\nInstalando...");

    char tid[20]={0}; int is_app=0;
    if(fn_gettid) fn_gettid(pkg_path,tid,&is_app);
    if(is_app&&fn_prepare) fn_prepare(pkg_path);

    int r=fn_install(pkg_path,0);
    g_last_inst=r;
    {char l[192];snprintf(l,sizeof(l),"install ret=0x%08x title=%s bytes=%d",(uint32_t)r,tid,dl_bytes);log_line(l);}

    if(r==0){
        strncpy(g_last_st,"ok",sizeof(g_last_st)-1);
        char resp[128]; snprintf(resp,sizeof(resp),
            "{\"status\":\"success\",\"bytes\":%d,\"title_id\":\"%s\"}",dl_bytes,tid);
        http_send(fd,200,resp);
        notify("PKGSender v8\nInstalacion completada!");
    } else {
        strncpy(g_last_st,"error",sizeof(g_last_st)-1);
        char msg[128]; snprintf(msg,sizeof(msg),
            "{\"status\":\"fail\",\"error\":\"appinst 0x%08x\",\"bytes\":%d}",(uint32_t)r,dl_bytes);
        http_send(fd,500,msg);
        char ntf[96]; snprintf(ntf,sizeof(ntf),"PKGSender ERROR\n0x%08x",(uint32_t)r);
        notify(ntf);
    }
}

/* ── do_install — descarga + instala ────────────────────────────────────── */
static void do_install(int fd, const char *url_raw)
{
    char url[2048]; memset(url,0,sizeof(url));
    url_decode(url_raw,url,sizeof(url));
    if(!url[0]){http_send(fd,400,"{\"status\":\"fail\",\"error\":\"URL vacia\"}");return;}
    if(strncmp(url,"https://",8)==0){
        http_send(fd,500,"{\"status\":\"fail\",\"error\":\"HTTPS no soportado. Usa http://IP:puerto/pkg\"}");return;}
    if(strncmp(url,"http://",7)!=0){
        http_send(fd,400,"{\"status\":\"fail\",\"error\":\"URL invalida\"}");return;}

    /* Verificar IP literal */
    {char h[64],p[8];int pt=80;char d[256];url_decode(url,d,sizeof(d));
     if(parse_url(d,h,sizeof(h),p,sizeof(p),&pt)==0){
         struct in_addr a;memset(&a,0,sizeof(a));
         if(sceNetInetPton(AF_INET,h,&a)!=1){
             char msg[256];snprintf(msg,sizeof(msg),
                 "{\"status\":\"fail\",\"error\":\"Hostname '%s' no soportado. Usa IP\"}",h);
             http_send(fd,500,msg);return;}}}

    strncpy(g_last_url,url,sizeof(g_last_url)-1);
    strncpy(g_last_st,"downloading",sizeof(g_last_st)-1);
    notify("PKGSender v8\nDescargando...");
    {char l[256];snprintf(l,sizeof(l),"download_start url=%.200s",url);log_line(l);}

    int64_t bytes=0;
    int dr=download_pkg(url,TMP_PKG,&bytes);
    g_last_bytes=(int)bytes;
    if(dr!=0){
        strncpy(g_last_st,"dl_error",sizeof(g_last_st)-1);
        char msg[128];snprintf(msg,sizeof(msg),
            "{\"status\":\"fail\",\"error\":\"descarga fallida %d\",\"bytes\":%d}",dr,(int)bytes);
        log_line(msg);http_send(fd,500,msg);
        notify("PKGSender ERROR\nDescarga fallida");return;
    }
    {char l[64];snprintf(l,sizeof(l),"download_ok bytes=%d",(int)bytes);log_line(l);}
    run_install(fd,TMP_PKG,(int)bytes);
}

/* ── do_install_local ────────────────────────────────────────────────────── */
static void do_install_local(int fd, const char *path)
{
    if(!path||!path[0]){http_send(fd,400,"{\"status\":\"fail\",\"error\":\"path vacio\"}");return;}
    strncpy(g_last_url,path,sizeof(g_last_url)-1);
    run_install(fd,path,0);
}

/* ── handle_client (mismo patrón que v5, buf[16384]) ────────────────────── */
static void handle_client(int fd)
{
    char buf[16384];
    memset(buf,0,sizeof(buf));

    /* Leer headers + body completo (body puede llegar en paquete separado) */
    int total=0;
    while(total<(int)sizeof(buf)-1){
        int n=sceNetRecv(fd,buf+total,sizeof(buf)-1-total,0);
        if(n<=0)break;
        total+=n; buf[total]='\0';
        char *he=strstr(buf,"\r\n\r\n");
        if(!he)continue;
        int bstart=(int)(he-buf)+4;
        char *cl=strstr(buf,"\r\nContent-Length:");
        if(!cl)cl=strstr(buf,"\r\ncontent-length:");
        if(cl){
            int clen=atoi(cl+17);
            int have=total-bstart;
            while(have<clen&&total<(int)sizeof(buf)-1){
                n=sceNetRecv(fd,buf+total,sizeof(buf)-1-total,0);
                if(n<=0)break;
                total+=n; have+=n; buf[total]='\0';
            }
        }
        break;
    }
    if(total<=0){sceNetSocketClose(fd);return;}

    if(strncmp(buf,"OPTIONS",7)==0){http_send(fd,204,"");sceNetSocketClose(fd);return;}

    if(strncmp(buf,"GET /ping",9)==0||strncmp(buf,"GET / ",6)==0){
        http_send(fd,200,"{\"status\":\"success\",\"version\":\"8.3\",\"port\":12800}");
        sceNetSocketClose(fd);return;}

    if(strncmp(buf,"GET /shutdown",13)==0){
        http_send(fd,200,"{\"status\":\"success\",\"message\":\"detenido\"}");
        sceNetSocketClose(fd);
        notify("PKGSender\nDetenido");
        g_shutdown=1;
        if(g_srv_fd>=0)sceNetSocketClose(g_srv_fd);
        return;}

    if(strncmp(buf,"GET /api/status",15)==0||strncmp(buf,"GET /status",11)==0){
        char resp[128];snprintf(resp,sizeof(resp),
            "{\"status\":\"success\",\"state\":\"%s\",\"last_ret\":\"0x%08x\"}",
            g_last_st,(uint32_t)g_last_inst);
        http_send(fd,200,resp);sceNetSocketClose(fd);return;}

    if(strncmp(buf,"GET /api/debug",14)==0){
        ai_ensure();
        char resp[512];snprintf(resp,sizeof(resp),
            "{\"status\":\"success\",\"version\":\"8.3\","
            "\"firmware\":\"%s\",\"firmware_raw\":\"0x%08x\","
            "\"appinst\":%s,\"appinst_detail\":\"%s\","
            "\"last_ret\":\"0x%08x\",\"last_bytes\":%d,"
            "\"gsched\":%d,\"ffsalloc\":%d,"
            "\"state\":\"%s\",\"last_url\":\"%s\"}",
            g_fw,g_fw_raw,
            g_ai_loaded==1?"true":"false",g_ai_detail,
            (uint32_t)g_last_inst,g_last_bytes,
            g_gsched,g_ffsalloc,
            g_last_st,g_last_url);
        http_send(fd,200,resp);sceNetSocketClose(fd);return;}

    if(strstr(buf,"/api/get_task_progress")!=NULL){
        char resp[128];snprintf(resp,sizeof(resp),
            "{\"status\":\"success\",\"result\":%d,"
            "\"length\":0,\"transferred_length\":%d}",
            g_last_inst==0?0:-1,g_last_bytes);
        http_send(fd,200,resp);sceNetSocketClose(fd);return;}

    if(strncmp(buf,"POST /api/is_exists",19)==0){
        http_send(fd,200,"{\"status\":\"success\",\"exists\":false,\"size\":0}");
        sceNetSocketClose(fd);return;}

    /* Body */
    char *body=strstr(buf,"\r\n\r\n"); if(body)body+=4;
    else{body=strstr(buf,"\n\n");if(body)body+=2;}
    if(!body)body=(char*)"";

    if(strncmp(buf,"POST /install_url",17)==0){
        if(!*body){http_send(fd,400,"{\"status\":\"fail\",\"error\":\"Body vacio\"}");sceNetSocketClose(fd);return;}
        do_install(fd,body);sceNetSocketClose(fd);return;}

    if(strncmp(buf,"POST /api/install",17)==0){
        if(!*body){http_send(fd,400,"{\"status\":\"fail\",\"error\":\"Body vacio\"}");sceNetSocketClose(fd);return;}
        char url[2048]={0};
        if(json_arr_first(body,"packages",url,sizeof(url))<=0)
            json_str(body,"url",url,sizeof(url));
        if(!url[0]){http_send(fd,400,"{\"status\":\"fail\",\"error\":\"Sin URL\"}");sceNetSocketClose(fd);return;}
        do_install(fd,url);sceNetSocketClose(fd);return;}

    if(strncmp(buf,"POST /install",13)==0){
        if(!*body){http_send(fd,400,"{\"status\":\"fail\",\"error\":\"Body vacio\"}");sceNetSocketClose(fd);return;}
        char url[2048]={0};
        if(json_str(body,"url",url,sizeof(url))<=0)
            json_str(body,"pkg_url",url,sizeof(url));
        if(!url[0]){http_send(fd,400,"{\"status\":\"fail\",\"error\":\"Campo url requerido\"}");sceNetSocketClose(fd);return;}
        do_install(fd,url);sceNetSocketClose(fd);return;}

    if(strncmp(buf,"POST /api/install_local",23)==0){
        if(!*body){http_send(fd,400,"{\"status\":\"fail\",\"error\":\"Body vacio\"}");sceNetSocketClose(fd);return;}
        char path[256]={0};
        if(json_str(body,"path",path,sizeof(path))<=0)
            strncpy(path,body,sizeof(path)-1);
        do_install_local(fd,path);sceNetSocketClose(fd);return;}

    http_send(fd,404,"{\"status\":\"fail\",\"error\":"
        "\"POST /install_url | POST /api/install | POST /install | "
        "POST /api/install_local | GET /api/debug | GET /shutdown\"}");
    sceNetSocketClose(fd);
}

/* ── Entry point (mismo patrón que v5) ───────────────────────────────────── */

/* ── Liberar instancia anterior en puerto 12800 ──────────────────────────
 * Conecta a 127.0.0.1:12800 y envía GET /shutdown.
 * Si hay un payload anterior activo, se cerrará limpiamente.
 * Si no hay nada escuchando, falla silenciosamente y continúa.
 * Espera hasta 2s para que el socket quede libre.
 * ───────────────────────────────────────────────────────────────────────── */
static void port_free_previous(void)
{
    struct in_addr lo; memset(&lo,0,sizeof(lo));
    sceNetInetPton(AF_INET,"127.0.0.1",&lo);

    int sk=sceNetSocket("kill_prev",AF_INET,SOCK_STREAM,0);
    if(sk<0) return;

    struct sockaddr_in sa; memset(&sa,0,sizeof(sa));
    sa.sin_family=AF_INET;
    sa.sin_port=sceNetHtons(12800);
    sa.sin_addr=lo;

    if(sceNetConnect(sk,(struct sockaddr*)&sa,sizeof(sa))==0){
        /* Hay algo escuchando — enviar shutdown */
        static const char req[]="GET /shutdown HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        sceNetSend(sk,(void*)req,sizeof(req)-1,0);
        /* Leer hasta que se cierre la conexión */
        char tmp[64]; int n;
        while((n=sceNetRecv(sk,tmp,sizeof(tmp),0))>0){}
        log_line("port_freed: shutdown sent to previous instance");
        /* Dar tiempo al proceso anterior para liberar el socket */
        sceKernelUsleep(500000); /* 0.5s */
    }
    sceNetSocketClose(sk);
}

int _main(void)
{
    initKernel();
    initLibc();
    initNetwork();
    initSysUtil();
    initModule();

    /* Firmware */
    {SceFwInfo i;memset(&i,0,sizeof(i));
     if(sceKernelGetSystemSwVersion&&sceKernelGetSystemSwVersion(&i)==0){
         g_fw_raw=i.version;
         if(i.version_string[0])strncpy(g_fw,i.version_string,sizeof(g_fw)-1);}}

    int jb=jailbreak();
    {char l[96];snprintf(l,sizeof(l),"boot v8.3 fw=%s jb=0x%08x",g_fw,(uint32_t)jb);log_line(l);}

    notify("PKGSender v8.3\nArrancando...");

    /* Liberar puerto 12800 si hay una instancia anterior activa */
    port_free_previous();

    /* Socket servidor */
    int srv=sceNetSocket("pkgsender_srv",AF_INET,SOCK_STREAM,0);
    if(srv<0){notify("PKGSender ERROR\nsocket fallo");return 1;}

    int opt=1;
    sceNetSetsockopt(srv,SCE_NET_SOL_SOCKET,SCE_NET_SO_REUSEADDR,&opt,sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_port=sceNetHtons(12800);
    addr.sin_addr.s_addr=IN_ADDR_ANY;

    if(sceNetBind(srv,(struct sockaddr*)&addr,sizeof(addr))<0){
        sceNetSocketClose(srv);notify("PKGSender ERROR\nPuerto 12800 ocupado");return 1;}
    if(sceNetListen(srv,8)<0){
        sceNetSocketClose(srv);notify("PKGSender ERROR\nlisten fallo");return 1;}

    g_srv_fd=srv;
    log_line("server_active");

    notify("PKGSender v8.3 ACTIVO\n:12800\nPOST /install_url = URL");

    for(;;){
        struct sockaddr_in ca; unsigned int cl=sizeof(ca);
        int cfd=sceNetAccept(srv,(struct sockaddr*)&ca,&cl);
        if(cfd<0){if(g_shutdown)break;continue;}
        handle_client(cfd);
        if(g_shutdown)break;
    }

    notify("PKGSender\nPuerto 12800 liberado");
    return 0;
}