/*
 * libjbc.h — Sandbox escape firmware-agnostic para PS4
 *
 * Implementación original: sleirsgoevy
 * https://github.com/sleirsgoevy/ps4-libjbc
 *
 * INSTRUCCIONES:
 * 1. Descarga ps4-libjbc desde el repositorio de sleirsgoevy
 * 2. Copia libjbc.a en este directorio (include/)
 * 3. El Makefile lo enlazará automáticamente
 *
 * Si estás usando OpenOrbis SDK, libjbc.a suele estar incluida en
 * $(OO_PS4_TOOLCHAIN)/lib/ y el Makefile ya la encontrará.
 *
 * En GoldHEN 2.3+ el proceso ya corre con privilegios, por lo que
 * jbc_run_as_root es un no-op y las llamadas igualmente funcionan.
 */

#pragma once

#include <sys/types.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct jbc_cred {
    uid_t    uid;
    uid_t    ruid;
    uid_t    svuid;
    short    rgid;
    short    pad0;
    uid_t    gid;
    uid_t    rgid2;
    uid_t    svgid;
    uintptr_t prison;
    uintptr_t cdir;
    uintptr_t rdir;
    uintptr_t jdir;
    uint64_t caps_lo;
    uint64_t caps_hi;
    uint32_t attr;
    uint8_t  pad1[0x58];
} jbc_cred;

/*
 * jbc_get_cred — copia las credenciales actuales del proceso
 * jbc_jailbreak_cred — modifica las credenciales para tener privilegios de shellcore
 * jbc_set_cred — aplica las credenciales modificadas
 * jbc_run_as_root — ejecuta fn(arg) con privilegios, luego restaura
 */
int  jbc_get_cred(jbc_cred *cred);
int  jbc_jailbreak_cred(jbc_cred *cred);
int  jbc_set_cred(const jbc_cred *cred);
void *jbc_run_as_root(void *(*fn)(void *), void *arg, int flags);

#ifdef __cplusplus
}
#endif
