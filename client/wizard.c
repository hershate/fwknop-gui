/**
 * \file client/wizard.c
 *
 * \brief Interactive `fwknop setup` wizard (plan Sec.7.1).
 *
 * Walks the user through the few inputs fwknop actually needs, then
 * generates everything else: a Rijndael key, an HMAC key, a TOTP seed
 * (for port-hopping), and a device fingerprint (SPA v4 device_id).  It
 * emits the corresponding client-side fwknoprc stanza, the server-side
 * access.conf stanza, and an otpauth:// URI, and can append the client
 * stanza to ~/.fwknoprc.
 */
#include "fwknop_common.h"
#include "fko.h"
#include "wizard.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* Minimal RFC 4648 base32 encoder (unpadded) for otpauth secrets.     */
/* Authenticators expect a base32 secret; our stored seed is base64 of */
/* the same raw bytes, so the two produce identical TOTP values.       */
/* ------------------------------------------------------------------ */
static int
b32_encode(const unsigned char *in, int len, char *out, int outsize)
{
    static const char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    int ob = 0, i, bitbuf = 0, bits = 0;

    for(i=0; i<len; i++)
    {
        bitbuf = (bitbuf << 8) | in[i];
        bits  += 8;
        while(bits >= 5)
        {
            if(ob >= outsize - 1)
                return -1;
            bits -= 5;
            out[ob++] = alpha[(bitbuf >> bits) & 0x1F];
        }
    }
    if(bits > 0)
    {
        if(ob >= outsize - 1)
            return -1;
        out[ob++] = alpha[(bitbuf << (5 - bits)) & 0x1F];
    }
    out[ob] = '\0';
    return ob;
}

/* ------------------------------------------------------------------ */
/* Prompt helpers.                                                     */
/* ------------------------------------------------------------------ */
static void
prompt_str(const char *prompt, const char *def, char *out, int outlen)
{
    char buf[MAX_LINE_LEN];

    printf("%s", prompt);
    if(def != NULL && def[0] != '\0')
        printf(" [%s]", def);
    printf(": ");
    fflush(stdout);

    if(fgets(buf, sizeof(buf), stdin) == NULL)
    {
        strlcpy(out, def != NULL ? def : "", outlen);
        return;
    }
    /* strip trailing newline */
    buf[strcspn(buf, "\r\n")] = '\0';
    if(buf[0] == '\0')
        strlcpy(out, def != NULL ? def : "", outlen);
    else
        strlcpy(out, buf, outlen);
}

static int
prompt_yn(const char *prompt, int def_yes)
{
    char buf[64];

    printf("%s [%s/%s]: ", prompt, def_yes ? "Y" : "y",
            def_yes ? "n" : "N");
    fflush(stdout);

    if(fgets(buf, sizeof(buf), stdin) == NULL)
        return def_yes;
    buf[0] = (char)tolower((unsigned char)buf[0]);
    if(buf[0] == 'y') return 1;
    if(buf[0] == 'n') return 0;
    return def_yes;
}

/* Default fwknoprc path: $USERPROFILE/.fwknoprc (Windows) or $HOME/.fwknoprc. */
static void
default_rc_path(char *out, int outlen)
{
    const char *home =
#ifdef WIN32
        getenv("USERPROFILE");
#else
        getenv("HOME");
#endif

    if(home == NULL)
        home = ".";
    snprintf(out, outlen, "%s%c.fwknoprc", home, PATH_SEP);
}

/* ------------------------------------------------------------------ */
int
wizard_setup(void)
{
    char stanza[128]    = "default";
    char server[256]    = {0};
    char username[128]  = {0};
    char access[256]    = "tcp/22";
    char allowip[128]   = {0};
    int  use_totp       = 1;
    char portrange[64]  = "30000-60000";
    int  write_rc       = 0;

    char key_b64[MAX_B64_KEY_LEN+1]      = {0};
    char hmac_b64[MAX_B64_KEY_LEN+1]     = {0};
    char trash_b64[MAX_B64_KEY_LEN+1]    = {0};
    char seed_b64[MAX_B64_KEY_LEN+1]     = {0};
    char seed_b32[MAX_B64_KEY_LEN+1]     = {0};
    char fp_b64[MAX_B64_KEY_LEN+1]       = {0};
    unsigned char seed_raw[MAX_B64_KEY_LEN];
    int  seed_raw_len                    = 0;

    printf("\n=== fwknop setup wizard ===\n");
    printf("Generates keys, TOTP seed, and a device fingerprint, and emits\n");
    printf("matching fwknoprc + access.conf stanzas.\n\n");

    prompt_str("Profile (stanza) name", stanza, stanza, sizeof(stanza));
    prompt_str("SPA server (host or IP)", NULL, server, sizeof(server));
    prompt_str("Username", getenv("USERNAME"), username, sizeof(username));
    prompt_str("Ports to open (e.g. tcp/22 or tcp/22,tcp/443)",
            access, access, sizeof(access));
    prompt_str("Client IP to allow (blank = resolve at knock time)",
            NULL, allowip, sizeof(allowip));
    use_totp = prompt_yn("Enable TOTP port-hopping?", 1);
    if(use_totp)
        prompt_str("Destination port range (START-END)",
                portrange, portrange, sizeof(portrange));

    /* ---- generate material ---- */
    if(fko_key_gen(key_b64, 0, hmac_b64, 0, FKO_HMAC_SHA256) != FKO_SUCCESS)
    {
        fprintf(stderr, "Error: key generation failed.\n");
        return EXIT_FAILURE;
    }

    /* TOTP seed: harvest a random base64 string via the public key-gen
     * API (the discarded Rijndael output), then decode it to raw bytes so
     * we can also emit a base32 secret for the otpauth URI.  Using only
     * exported fko_* APIs keeps the client linkable against libfko.so. */
    if(fko_key_gen(trash_b64, 0, seed_b64, 0, FKO_HMAC_SHA256) != FKO_SUCCESS)
    {
        fprintf(stderr, "Error: TOTP seed generation failed.\n");
        return EXIT_FAILURE;
    }
    seed_raw_len = fko_base64_decode(seed_b64, seed_raw);
    if(seed_raw_len <= 0)
    {
        fprintf(stderr, "Error: TOTP seed decode failed.\n");
        return EXIT_FAILURE;
    }
    b32_encode(seed_raw, seed_raw_len, seed_b32, sizeof(seed_b32));
    memset(seed_raw, 0, sizeof(seed_raw));
    memset(trash_b64, 0, sizeof(trash_b64));

    if(fko_gen_device_fingerprint(fp_b64, (int)sizeof(fp_b64)) != FKO_SUCCESS)
    {
        fprintf(stderr, "Error: device fingerprint generation failed.\n");
        return EXIT_FAILURE;
    }

    /* ---- emit client fwknoprc stanza ---- */
    printf("\n----- add to ~/.fwknoprc (client) -----\n");
    printf("[%s]\n", stanza);
    printf("SPA_SERVER             %s\n", server);
    printf("ACCESS                 %s\n", access);
    if(allowip[0] != '\0')
        printf("ALLOW_IP               %s\n", allowip);
    if(username[0] != '\0')
        printf("SPOOF_USER             %s\n", username);
    printf("KEY_BASE64             %s\n", key_b64);
    printf("HMAC_KEY_BASE64        %s\n", hmac_b64);
    printf("USE_HMAC               Y\n");
    printf("DEVICE_ID              %s\n", fp_b64);
    if(use_totp)
    {
        printf("USE_TOTP_PORT          Y\n");
        printf("TOTP_SEED_BASE64       %s\n", seed_b64);
        printf("PORT_RANGE             %s\n", portrange);
    }
    printf("\n");

    /* ---- emit server access.conf stanza ---- */
    printf("----- add to /etc/fwknop/access.conf (server) -----\n");
    printf("SOURCE                 %s\n", allowip[0] ? allowip : "ANY");
    printf("OPEN_PORTS             %s\n", access);
    printf("KEY_BASE64             %s\n", key_b64);
    printf("HMAC_KEY_BASE64        %s\n", hmac_b64);
    printf("FW_ACCESS_TIMEOUT     30\n");
    printf("REQUIRE_SOURCE_ADDRESS %s\n", allowip[0] ? "Y" : "N");
    printf("REQUIRE_FINGERPRINT    Y   # requires fwknopd fingerprint support\n");
    printf("FINGERPRINT            %s\n", fp_b64);
    printf("\n");

    /* ---- otpauth URI (visual reference for the TOTP seed) ---- */
    if(use_totp)
    {
        printf("----- otpauth URI (TOTP seed; scan into an authenticator) -----\n");
        printf("otpauth://totp/fwknop:%s?secret=%s&issuer=fwknop"
               "&algorithm=SHA256&digits=8&period=30\n",
               stanza, seed_b32);
        printf("(Render a QR with e.g.: qrencode -t ANSIUTF8 \"<uri>\")\n\n");
    }

    /* ---- optionally write the client stanza to ~/.fwknoprc ---- */
    write_rc = prompt_yn("Append this client stanza to ~/.fwknoprc now?", 0);
    if(write_rc)
    {
        char rcpath[MAX_PATH_LEN];
        FILE *rc;

        default_rc_path(rcpath, sizeof(rcpath));
        rc = fopen(rcpath, "a");
        if(rc == NULL)
        {
            fprintf(stderr, "Error: could not open %s for append.\n", rcpath);
            return EXIT_FAILURE;
        }
        fprintf(rc, "\n[%s]\n", stanza);
        fprintf(rc, "SPA_SERVER             %s\n", server);
        fprintf(rc, "ACCESS                 %s\n", access);
        if(allowip[0] != '\0')
            fprintf(rc, "ALLOW_IP               %s\n", allowip);
        if(username[0] != '\0')
            fprintf(rc, "SPOOF_USER             %s\n", username);
        fprintf(rc, "KEY_BASE64             %s\n", key_b64);
        fprintf(rc, "HMAC_KEY_BASE64        %s\n", hmac_b64);
        fprintf(rc, "USE_HMAC               Y\n");
        fprintf(rc, "DEVICE_ID              %s\n", fp_b64);
        if(use_totp)
        {
            fprintf(rc, "USE_TOTP_PORT          Y\n");
            fprintf(rc, "TOTP_SEED_BASE64       %s\n", seed_b64);
            fprintf(rc, "PORT_RANGE             %s\n", portrange);
        }
        fclose(rc);
        printf("Appended stanza [%s] to %s\n", stanza, rcpath);
    }

    /* Wipe sensitive generated material from stack buffers. */
    memset(key_b64, 0, sizeof(key_b64));
    memset(hmac_b64, 0, sizeof(hmac_b64));
    memset(seed_b64, 0, sizeof(seed_b64));

    printf("\nDone. On the client:  fwknop knock %s\n", stanza);
    return EXIT_SUCCESS;
}

/***EOF***/
