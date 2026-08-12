/**
 * \file client/import.c
 *
 * \brief `fwknop import` — turn a server-issued credential into a fwknoprc
 *        stanza (plan §7.6.3).
 *
 * Accepts three input forms, auto-detected:
 *   1. a fwknop:// URI (argument or a .txt file containing one)
 *   2. a credential JSON file (.json), optionally encrypted (fwknop-cred v1 enc)
 *   3. a QR image (.png/.jpg) holding a fwknop:// URI — decoded via `zbarimg`
 *      if available (optional runtime dep), else the user provides the URI.
 *
 * The client only uses exported fko_* APIs (fko_decrypt_buf for encrypted
 * files) and its own small JSON/URI readers, keeping the client decoupled
 * from server-side code (same convention as wizard.c).
 */
#include "fwknop_common.h"
#include "fko.h"
#include "import.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define IMP_FIELD_LEN 300

typedef struct {
    char stanza[IMP_FIELD_LEN];
    char spa_server[IMP_FIELD_LEN];
    char access[IMP_FIELD_LEN];
    char key_base64[IMP_FIELD_LEN];
    char hmac_key_base64[IMP_FIELD_LEN];
    char totp_seed_base64[IMP_FIELD_LEN];
    char port_range[IMP_FIELD_LEN];
    char device_id[IMP_FIELD_LEN];
    char username[IMP_FIELD_LEN];
} imp_cred_t;

/* ------------------------------------------------------------------ */
/* tiny JSON string extractor (same shape as server credential.c)      */
/* ------------------------------------------------------------------ */
static int
json_get_str(const char *json, const char *key, char *out, size_t out_sz)
{
    char needle[64];
    const char *p, *q;
    size_t i = 0;
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    p = strstr(json, needle);
    if(p == NULL) return 0;
    p += strlen(needle);
    while(*p && (*p == ' ' || *p == '\t' || *p == ':')) p++;
    if(*p != '"') return 0;
    p++; q = p;
    while(*q && *q != '"' && i + 1 < out_sz)
    {
        if(*q == '\\' && (q[1] == '"' || q[1] == '\\')) q++;
        out[i++] = *q++;
    }
    out[i] = '\0';
    return 1;
}

/* URL-safe base64 restore (+/-, /_, pad). In place. */
static void
b64_from_urlsafe(char *s)
{
    size_t n = strlen(s), pad;
    for(; *s; s++)
    {
        if(*s == '-') *s = '+';
        else if(*s == '_') *s = '/';
    }
    pad = (4 - (n % 4)) % 4;
    if(pad > 0)
    {
        char *end = s + n;
        while(pad-- > 0) *end++ = '=';
        *end = '\0';
    }
}

static int
uri_get_param(const char *uri, const char *key, char *out, size_t out_sz)
{
    char needle[64];
    const char *p;
    size_t i = 0;
    snprintf(needle, sizeof(needle), "%s=", key);
    p = strchr(uri, '?');
    if(p == NULL) p = uri;
    p = strstr(p, needle);
    if(p == NULL)
    {
        snprintf(needle, sizeof(needle), "&%s=", key);
        p = strstr(uri, needle);
        if(p == NULL) return 0;
        p += 1;
    }
    p += strlen(key) + 1;
    while(*p && *p != '&' && *p != '#' && i + 1 < out_sz)
        out[i++] = *p++;
    out[i] = '\0';
    return i > 0;
}

static int
parse_uri(const char *uri, imp_cred_t *c)
{
    const char *host_end;
    size_t host_len;
    if(strncmp(uri, "fwknop://", 9) != 0) return -1;
    host_end = strchr(uri + 9, '?');
    host_len = host_end ? (size_t)(host_end - (uri + 9)) : strlen(uri + 9);
    if(host_len >= sizeof(c->spa_server)) host_len = sizeof(c->spa_server) - 1;
    memcpy(c->spa_server, uri + 9, host_len);
    c->spa_server[host_len] = '\0';

    uri_get_param(uri, "name",  c->stanza, sizeof(c->stanza));
    uri_get_param(uri, "access", c->access, sizeof(c->access));
    uri_get_param(uri, "range", c->port_range, sizeof(c->port_range));
    uri_get_param(uri, "user",  c->username, sizeof(c->username));
    if(uri_get_param(uri, "key",  c->key_base64, sizeof(c->key_base64)))
        b64_from_urlsafe(c->key_base64);
    if(uri_get_param(uri, "hmac", c->hmac_key_base64, sizeof(c->hmac_key_base64)))
        b64_from_urlsafe(c->hmac_key_base64);
    if(uri_get_param(uri, "totp", c->totp_seed_base64, sizeof(c->totp_seed_base64)))
        b64_from_urlsafe(c->totp_seed_base64);

    if(c->key_base64[0] == '\0' || c->hmac_key_base64[0] == '\0')
        return -2;
    return 0;
}

static int
parse_json(const char *json, imp_cred_t *c)
{
    json_get_str(json, "stanza",        c->stanza, sizeof(c->stanza));
    json_get_str(json, "spa_server",    c->spa_server, sizeof(c->spa_server));
    json_get_str(json, "access",        c->access, sizeof(c->access));
    json_get_str(json, "key_base64",    c->key_base64, sizeof(c->key_base64));
    json_get_str(json, "hmac_key_base64", c->hmac_key_base64, sizeof(c->hmac_key_base64));
    json_get_str(json, "totp_seed_base64", c->totp_seed_base64, sizeof(c->totp_seed_base64));
    json_get_str(json, "port_range",    c->port_range, sizeof(c->port_range));
    json_get_str(json, "device_id",     c->device_id, sizeof(c->device_id));
    json_get_str(json, "username",      c->username, sizeof(c->username));
    if(c->key_base64[0] == '\0' || c->hmac_key_base64[0] == '\0')
        return -2;
    return 0;
}

/* ------------------------------------------------------------------ */
static void
default_rc_path(char *out, int outlen)
{
    const char *home =
#ifdef WIN32
        getenv("USERPROFILE");
#else
        getenv("HOME");
#endif
    if(home == NULL) home = ".";
    snprintf(out, outlen, "%s%c.fwknoprc", home, PATH_SEP);
}

static int
write_stanza(const char *rcpath, const imp_cred_t *c)
{
    FILE *rc = fopen(rcpath, "a");
    if(rc == NULL)
    {
        fprintf(stderr, "import: cannot open %s: %s\n", rcpath, strerror(errno));
        return -1;
    }
    fprintf(rc, "\n[%s]\n", c->stanza);
    fprintf(rc, "SPA_SERVER             %s\n", c->spa_server);
    fprintf(rc, "ACCESS                 %s\n", c->access[0] ? c->access : "tcp/22");
    if(c->username[0])
        fprintf(rc, "SPOOF_USER             %s\n", c->username);
    fprintf(rc, "KEY_BASE64             %s\n", c->key_base64);
    fprintf(rc, "HMAC_KEY_BASE64        %s\n", c->hmac_key_base64);
    fprintf(rc, "USE_HMAC               Y\n");
    if(c->device_id[0])
        fprintf(rc, "DEVICE_ID              %s\n", c->device_id);
    if(c->totp_seed_base64[0])
    {
        fprintf(rc, "USE_TOTP_PORT          Y\n");
        fprintf(rc, "TOTP_SEED_BASE64       %s\n", c->totp_seed_base64);
        fprintf(rc, "PORT_RANGE             %s\n",
                c->port_range[0] ? c->port_range : "30000-60000");
    }
    fclose(rc);
    return 0;
}

/* Read a whole file into a malloc'd buffer. */
static char *
read_file(const char *path, long *len_out)
{
    FILE *f = fopen(path, "r");
    long sz; char *buf;
    if(f == NULL) return NULL;
    fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, 0, SEEK_SET);
    if(sz < 0) { fclose(f); return NULL; }
    buf = malloc((size_t)sz + 1);
    if(buf == NULL) { fclose(f); return NULL; }
    if(fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    buf[sz] = '\0';
    fclose(f);
    if(len_out) *len_out = sz;
    return buf;
}

int
cli_import(int argc, char **argv)
{
    const char *src = NULL, *name_override = NULL, *rcpath_arg = NULL;
    const char *passphrase = NULL;
    char defrc[MAX_PATH_LEN];
    const char *rcpath;
    imp_cred_t cred;
    char *content = NULL;
    long content_len = 0;
    int rc, i;

    for(i = 2; i < argc; i++)
    {
        if(strcmp(argv[i], "--name") == 0 && i+1 < argc)
            name_override = argv[++i];
        else if(strcmp(argv[i], "--rc-file") == 0 && i+1 < argc)
            rcpath_arg = argv[++i];
        else if(strcmp(argv[i], "--passphrase") == 0 && i+1 < argc)
            passphrase = argv[++i];
        else if(argv[i][0] != '-')
            src = argv[i];
        else
        {
            fprintf(stderr, "import: unknown option %s\n", argv[i]);
            return EXIT_FAILURE;
        }
    }

    if(src == NULL)
    {
        fprintf(stderr,
            "usage: fwknop import <fwknop://uri | cred.json | qr.png> "
            "[--name N] [--rc-file F] [--passphrase P]\n");
        return EXIT_FAILURE;
    }

    memset(&cred, 0, sizeof(cred));

    /* Case 1: argument is a fwknop:// URI directly. */
    if(strncmp(src, "fwknop://", 9) == 0)
    {
        if(parse_uri(src, &cred) != 0)
        {
            fprintf(stderr, "import: invalid fwknop:// URI\n");
            return EXIT_FAILURE;
        }
    }
    else
    {
        /* Case 2/3: it's a file path. Read it. */
        char *nl;
        /* If it looks like an image, try zbarimg. */
        {
            const char *ext = strrchr(src, '.');
            if(ext && (strcmp(ext, ".png") == 0 || strcmp(ext, ".jpg") == 0
                       || strcmp(ext, ".jpeg") == 0))
            {
                char cmd[1024];
                snprintf(cmd, sizeof(cmd),
                    "zbarimg --quiet --raw '%s' 2>/dev/null", src);
                {
                    FILE *pp = popen(cmd, "r");
                    char ubuf[2048];
                    size_t un;
                    if(pp == NULL)
                    {
                        fprintf(stderr,
                            "import: cannot decode QR (zbarimg missing?)\n");
                        return EXIT_FAILURE;
                    }
                    un = fread(ubuf, 1, sizeof(ubuf) - 1, pp);
                    ubuf[un] = '\0';
                    pclose(pp);
                    /* find fwknop:// in the decoded text */
                    {
                        char *u = strstr(ubuf, "fwknop://");
                        if(u == NULL)
                        {
                            fprintf(stderr, "import: no fwknop:// in QR\n");
                            return EXIT_FAILURE;
                        }
                        nl = strchr(u, '\n'); if(nl) *nl = '\0';
                        if(parse_uri(u, &cred) != 0)
                        {
                            fprintf(stderr, "import: invalid URI from QR\n");
                            return EXIT_FAILURE;
                        }
                        goto parsed;
                    }
                }
            }
        }

        content = read_file(src, &content_len);
        if(content == NULL)
        {
            fprintf(stderr, "import: cannot read %s\n", src);
            return EXIT_FAILURE;
        }

        /* A file could itself be a bare fwknop:// URI (from console output). */
        if(strncmp(content, "fwknop://", 9) == 0)
        {
            nl = strchr(content, '\n'); if(nl) *nl = '\0';
            /* also strip trailing whitespace */
            {
                char *e = content + strlen(content);
                while(e > content && (e[-1] == '\r' || e[-1] == ' ' || e[-1]=='\t'))
                    *--e = '\0';
            }
            if(parse_uri(content, &cred) != 0)
            {
                fprintf(stderr, "import: invalid fwknop:// URI in file\n");
                free(content);
                return EXIT_FAILURE;
            }
        }
        else if(strncmp(content, "fwknop-cred v1 enc", 18) == 0)
        {
            /* Encrypted credential: first line is the magic, rest is b64 ct. */
            char *b64 = content + 18;
            unsigned char *pt;
            int pt_len;
            const char *pass = passphrase;
            char passbuf[256] = {0};
            while(*b64 == '\n' || *b64 == '\r' || *b64 == ' ') b64++;
            if(pass == NULL)
            {
                printf("Passphrase: "); fflush(stdout);
                if(fgets(passbuf, sizeof(passbuf), stdin) == NULL)
                { free(content); return EXIT_FAILURE; }
                passbuf[strcspn(passbuf, "\r\n")] = '\0';
                pass = passbuf;
            }
            pt = malloc((size_t)content_len);
            if(pt == NULL) { free(content); return EXIT_FAILURE; }
            pt_len = fko_decrypt_buf(pass, (int)strlen(pass), b64, pt,
                    (int)content_len);
            if(pt_len <= 0)
            {
                fprintf(stderr, "import: decryption failed (wrong passphrase?)\n");
                free(pt); free(content);
                memset(passbuf, 0, sizeof(passbuf));
                return EXIT_FAILURE;
            }
            pt[pt_len] = '\0';
            {
                int pr = parse_json((char *)pt, &cred);
                memset(pt, 0, pt_len);
                free(pt);
                memset(passbuf, 0, sizeof(passbuf));
                if(pr != 0)
                {
                    fprintf(stderr, "import: decrypted credential is invalid\n");
                    free(content);
                    return EXIT_FAILURE;
                }
            }
        }
        else
        {
            /* Plaintext JSON credential. */
            if(parse_json(content, &cred) != 0)
            {
                fprintf(stderr, "import: invalid credential JSON\n");
                free(content);
                return EXIT_FAILURE;
            }
        }
        free(content);
    }

parsed:
    if(name_override != NULL && name_override[0])
        strlcpy(cred.stanza, name_override, sizeof(cred.stanza));
    if(cred.stanza[0] == '\0')
        strlcpy(cred.stanza, "imported", sizeof(cred.stanza));

    rcpath = (rcpath_arg != NULL) ? rcpath_arg
            : (default_rc_path(defrc, sizeof(defrc)), defrc);

    rc = write_stanza(rcpath, &cred);
    if(rc != 0)
        return EXIT_FAILURE;

    printf("Imported stanza [%s] into %s\n", cred.stanza, rcpath);
    printf("  server=%s access=%s totp=%s\n",
            cred.spa_server,
            cred.access[0] ? cred.access : "tcp/22",
            cred.totp_seed_base64[0] ? "yes" : "no");
    printf("Knock with: fwknop knock %s\n", cred.stanza);

    /* wipe sensitive fields */
    memset(&cred, 0, sizeof(cred));
    return EXIT_SUCCESS;
}

/***EOF***/
