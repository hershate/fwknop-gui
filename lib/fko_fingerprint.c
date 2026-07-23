/**
 * \file lib/fko_fingerprint.c
 *
 * \brief Generate a per-device fingerprint (plan Appendix C).
 *
 * Lives in libfko so it can use the internal SHA-256 / base64 helpers
 * directly; it is exported via the public `fko_gen_device_fingerprint`
 * API (the libfko export regex is `^fko_`).  Only the hashed digest ever
 * leaves the host -- no plaintext hardware attributes are transmitted.
 *
 * Collects a small set of stable, cross-platform attributes, concatenates
 * them in a fixed canonical order, SHA-256 hashes, and emits the first 16
 * bytes as base64.  Attributes vary by platform (we "take what exists"):
 *  - Windows: hostname, registry MachineGuid, system-drive volume serial
 *  - Unix:    hostname, /etc/machine-id
 * More entropy (disk/mainboard UUID) can be added later without changing
 * the contract.
 */
#include "fko_common.h"
#include "fko.h"
#include "digest.h"

#ifdef WIN32
  #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0600   /* RegGetValueA */
  #endif
  #include <windows.h>
  #include <winreg.h>
#endif

#include <string.h>
#include <stdio.h>

/* First 16 bytes of the SHA-256 digest (Appendix C). */
#define FP_BYTES 16

#ifdef WIN32
static void
fp_read_machine_guid(char *buf, const int bufsize)
{
    DWORD   len = (DWORD)bufsize;
    LSTATUS rc;

    buf[0] = '\0';
    rc = RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography",
            "MachineGuid", RRF_RT_REG_SZ, NULL, buf, &len);
    if(rc != ERROR_SUCCESS)
        buf[0] = '\0';
}
#endif

/* Generate a stable per-device fingerprint as base64. */
DLL_API int
fko_gen_device_fingerprint(char *out_b64, const int out_b64_len)
{
    char            canon[512];
    unsigned char   full[32];        /* full SHA-256 digest */
    unsigned char   head[FP_BYTES];  /* first 16 bytes */

    if(out_b64 == NULL || out_b64_len < 32)
        return FKO_ERROR_INVALID_DATA;

    memset(canon, 0, sizeof(canon));

#ifdef WIN32
    {
        char    host[256]   = {0};
        char    guid[128]   = {0};
        char    sysdir[260] = {0};
        DWORD   hostlen     = (DWORD)sizeof(host);
        DWORD   volserial    = 0;

        GetComputerNameA(host, &hostlen);
        fp_read_machine_guid(guid, sizeof(guid));
        if(GetSystemDirectoryA(sysdir, sizeof(sysdir)) > 0)
        {
            char root[4] = { sysdir[0], ':', '\\', 0 };
            GetVolumeInformationA(root, NULL, 0, &volserial, NULL, NULL, NULL, 0);
        }
        snprintf(canon, sizeof(canon), "%s|%s|%lu",
                host, guid, (unsigned long)volserial);
    }
#else
    {
        char  host[256] = {0};
        char  mid[128]  = {0};
        FILE *f = fopen("/etc/machine-id", "r");

        gethostname(host, sizeof(host) - 1);
        if(f != NULL)
        {
            if(fgets(mid, sizeof(mid), f) != NULL)
                mid[strcspn(mid, "\r\n ")] = '\0';
            fclose(f);
        }
        snprintf(canon, sizeof(canon), "%s|%s", host, mid);
    }
#endif

    sha256(full, (unsigned char *)canon, (size_t)strlen(canon));
    memcpy(head, full, FP_BYTES);

    memset(canon, 0, sizeof(canon));
    memset(full, 0, sizeof(full));

    fko_base64_encode(head, out_b64, FP_BYTES); /* 16 bytes -> 24 b64 chars + NUL */

    memset(head, 0, sizeof(head));
    return FKO_SUCCESS;
}

/***EOF***/
