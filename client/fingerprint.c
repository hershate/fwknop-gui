/**
 * \file client/fingerprint.c
 *
 * \brief Device fingerprint generation (plan Appendix C).
 *
 * Collects a small set of stable, cross-platform host attributes,
 * concatenates them in a fixed canonical order, then SHA-256 hashes
 * the result and emits the first 16 bytes as base64.  Only the hash
 * is ever sent (as the SPA v4 device_id).  Attributes available vary
 * by platform (per the spec we "take what exists"); on Windows we use
 * the hostname, the registry MachineGuid, and the system-drive volume
 * serial.  More entropy (e.g. disk/mainboard UUID via WMI) can be
 * added later without changing the contract.
 */
/* Ensure RegGetValueA is declared (needs _WIN32_WINNT >= 0x0600). */
#ifdef WIN32
  #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0600
  #endif
#endif

#include "common.h"
#include "fko.h"        /* fko_base64_encode */
#include "digest.h"     /* sha256 */
#include "fingerprint.h"

#ifdef WIN32
  #include <windows.h>
  #include <winreg.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Take the first 16 bytes of the SHA-256 digest (Appendix C). */
#define FP_BYTES 16

#ifdef WIN32

/* Read HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid into buf. */
static void
fp_read_machine_guid(char *buf, const int bufsize)
{
    DWORD len = (DWORD)bufsize;
    LSTATUS rc;

    buf[0] = '\0';
    rc = RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography",
            "MachineGuid", RRF_RT_REG_SZ, NULL, buf, &len);
    if(rc != ERROR_SUCCESS)
        buf[0] = '\0';
}

#endif /* WIN32 */

int
gen_device_fingerprint(char *out_b64, const int out_b64_len)
{
    char            canon[512];
    unsigned char   full[32];        /* full SHA-256 digest */
    unsigned char   head[FP_BYTES];  /* first 16 bytes */

    if(out_b64 == NULL || out_b64_len < 32)
        return -1;

    memset(canon, 0, sizeof(canon));

#ifdef WIN32
    {
        char    host[256]  = {0};
        char    guid[128]  = {0};
        char    sysdir[260]= {0};
        DWORD   hostlen    = (DWORD)sizeof(host);
        DWORD   volserial  = 0;

        GetComputerNameA(host, &hostlen);
        fp_read_machine_guid(guid, sizeof(guid));

        /* System-drive volume serial: derive the drive from the system dir. */
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
        /* Linux / Unix: hostname + /etc/machine-id (best effort).
         * The full Linux attribute set is implemented in the Linux env. */
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

    /* Wipe intermediates that hold identifying material. */
    memset(canon, 0, sizeof(canon));
    memset(full, 0, sizeof(full));

    fko_base64_encode(head, out_b64, FP_BYTES); /* 16 bytes -> 24 b64 chars + NUL */

    memset(head, 0, sizeof(head));
    return 0;
}

/***EOF***/
