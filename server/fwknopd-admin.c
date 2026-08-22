/**
 * \file server/fwknopd-admin.c
 *
 * \brief Server-side administration CLI (plan Sec.7.6).
 *
 * Carries all server management logic: stanza management, key/seed/fingerprint
 * generation, authorization QR (fwknop://), encrypted credential export, TOFU
 * binding management. WebUI/TUI front-ends wrap this tool rather than
 * re-implementing key handling.
 *
 *   fwknopd-admin user add <name> [opts]   generate material + print stanzas
 *   fwknopd-admin user list                list access.conf stanzas
 *   fwknopd-admin user rm <name>           remove a stanza
 *   fwknopd-admin user qr <name>           re-render an authorization QR
 *   fwknopd-admin user export <name> -o f  write credential file (encrypted)
 *   fwknopd-admin tofu list|unbind <id>    manage TOFU state file
 *   fwknopd-admin lint [access.conf]       check stanza consistency
 *   fwknopd-admin status                   quick health
 *
 * Only uses exported fko_* APIs + server-side credential/access helpers.
 */
#include "fwknopd_common.h"
#include "fko.h"
#include "fko_totp.h"
#include "credential.h"
#include "access.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>

#define DEFAULT_PORT_RANGE  "30000-60000"
#define DEFAULT_ACCESS_CONF "/etc/fwknop/access.conf"
#define DEFAULT_TOFU_STATE  "/var/run/fwknop/fwknop_tofu.state"
#define DEFAULT_PID_FILE    "/var/run/fwknop/fwknopd.pid"

/* ------------------------------------------------------------------ */
/* QR rendering: try qrencode (optional runtime dep); else print URI.  */
/* ------------------------------------------------------------------ */
static void
render_qr(const char *uri)
{
    char cmd[2048];
    int rc;
    snprintf(cmd, sizeof(cmd),
        "qrencode -t ANSIUTF8 '%s' 2>/dev/null", uri);
    rc = system(cmd);
    if(rc != 0)
    {
        printf("(qrencode not available; URI below can be piped to it)\n");
        printf("%s\n", uri);
        printf("  e.g.: qrencode -t ANSIUTF8 '%s'\n", uri);
    }
}

/* ------------------------------------------------------------------ */
/* Generate keys + TOTP seed + (optionally) device fingerprint.         */
/* ------------------------------------------------------------------ */
static int
gen_material(fwknop_credential_t *c, int gen_fingerprint, int use_totp)
{
    char trash_b64[CRED_FIELD_LEN] = {0};
    unsigned char seed_raw[CRED_FIELD_LEN];
    int seed_raw_len = 0;

    if(fko_key_gen(c->key_base64, 0, c->hmac_key_base64, 0,
            FKO_HMAC_SHA256) != FKO_SUCCESS)
    {
        fprintf(stderr, "[*] key generation failed\n");
        return -1;
    }
    if(use_totp)
    {
        if(fko_key_gen(trash_b64, 0, c->totp_seed_base64, 0,
                FKO_HMAC_SHA256) != FKO_SUCCESS)
        {
            fprintf(stderr, "[*] TOTP seed generation failed\n");
            return -1;
        }
        seed_raw_len = fko_base64_decode(c->totp_seed_base64, seed_raw);
        (void)seed_raw_len;
        memset(seed_raw, 0, sizeof(seed_raw));
        memset(trash_b64, 0, sizeof(trash_b64));
    }
    if(gen_fingerprint)
    {
        if(fko_gen_device_fingerprint(c->device_id,
                (int)sizeof(c->device_id)) != FKO_SUCCESS)
        {
            fprintf(stderr, "[*] device fingerprint generation failed\n");
            return -1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Print the server access.conf stanza.                                 */
/* ------------------------------------------------------------------ */
static void
print_access_stanza(const fwknop_credential_t *c, int require_fp,
        int require_port_match, int tofu_timeout)
{
    printf("----- add to /etc/fwknop/access.conf (server) -----\n");
    printf("### fwknopd-admin user: %s\n", c->stanza);
    printf("SOURCE                 ANY\n");
    if(c->username[0])
        printf("REQUIRE_USERNAME       %s\n", c->username);
    printf("OPEN_PORTS             %s\n", c->access[0] ? c->access : "tcp/22");
    printf("KEY_BASE64             %s\n", c->key_base64);
    printf("HMAC_KEY_BASE64        %s\n", c->hmac_key_base64);
    printf("FW_ACCESS_TIMEOUT      30\n");
    if(c->totp_seed_base64[0])
    {
        printf("TOTP_SEED_BASE64       %s\n", c->totp_seed_base64);
        printf("TOTP_PORT_RANGE        %s\n", c->port_range);
    }
    if(require_fp)
    {
        printf("REQUIRE_FINGERPRINT    Y\n");
        if(tofu_timeout > 0)
            printf("FINGERPRINT_TOFU_TIMEOUT %d\n", tofu_timeout);
        else if(c->device_id[0])
            printf("FINGERPRINT            %s\n", c->device_id);
    }
    if(require_port_match && c->totp_seed_base64[0])
        printf("REQUIRE_TOTP_PORT_MATCH Y\n");
    printf("\n");
}

/* ------------------------------------------------------------------ */
/* Write a credential file. Encrypted by default (passphrase prompt).  */
/* ------------------------------------------------------------------ */
static int
write_credential_file(const fwknop_credential_t *c, const char *path,
        int plain)
{
    char json[CRED_JSON_MAX];
    FILE *fp;

    credential_to_json(c, json, sizeof(json));

    fp = fopen(path, "w");
    if(fp == NULL)
    {
        fprintf(stderr, "[*] cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    chmod(path, 0600);

    if(plain)
    {
        fputs(json, fp);
        fputc('\n', fp);
    }
    else
    {
        char pass[256] = {0};
        char pass2[256] = {0};
        char *enc_b64 = NULL;
        int enc_len;

        printf("Passphrase to protect the credential file: ");
        fflush(stdout);
        if(fgets(pass, sizeof(pass), stdin) == NULL)
        { fclose(fp); return -1; }
        pass[strcspn(pass, "\r\n")] = '\0';
        printf("Confirm passphrase: ");
        fflush(stdout);
        if(fgets(pass2, sizeof(pass2), stdin) == NULL)
        { fclose(fp); return -1; }
        pass2[strcspn(pass2, "\r\n")] = '\0';
        if(strcmp(pass, pass2) != 0)
        {
            fprintf(stderr, "[*] passphrases do not match\n");
            fclose(fp);
            memset(pass, 0, sizeof(pass));
            memset(pass2, 0, sizeof(pass2));
            return -1;
        }

        enc_b64 = malloc(strlen(json) * 2 + 128);
        if(enc_b64 == NULL)
        { fclose(fp); return -1; }
        enc_len = fko_encrypt_buf(pass, (int)strlen(pass),
                (unsigned char *)json, (int)strlen(json),
                enc_b64, (int)(strlen(json) * 2 + 128));
        if(enc_len <= 0)
        {
            fprintf(stderr, "[*] encryption failed\n");
            free(enc_b64);
            fclose(fp);
            memset(pass, 0, sizeof(pass));
            return -1;
        }
        fprintf(fp, "fwknop-cred v1 enc\n");
        fputs(enc_b64, fp);
        fputc('\n', fp);
        free(enc_b64);
        memset(pass, 0, sizeof(pass));
        memset(pass2, 0, sizeof(pass2));
    }
    fclose(fp);
    printf("Credential written to %s (%s)\n", path,
            plain ? "plaintext" : "encrypted");
    return 0;
}

/* ------------------------------------------------------------------ */
/* access.conf stanza model (line-based). Stanzas begin with SOURCE;   */
/* "user add" output carries a "### fwknopd-admin user: <name>" marker */
/* so stanzas can be identified by credential name later.              */
/* ------------------------------------------------------------------ */
#define MAX_STANZAS 64
#define MAX_LINE    2048

typedef struct {
    int  start_line;                 /* 1-based line of the SOURCE directive */
    int  end_line;                   /* inclusive */
    int  name_line;                  /* line of the "### fwknopd-admin user:" marker, 0 if none */
    char name[128];                  /* marker comment or REQUIRE_USERNAME   */
    char source[256];
    char require_username[128];
    char open_ports[256];
    char fw_access_timeout[32];
    char key_base64[CRED_FIELD_LEN];
    char hmac_key_base64[CRED_FIELD_LEN];
    char totp_seed_base64[CRED_FIELD_LEN];
    char port_range[64];
    int  tofu_timeout;
    int  has_key, has_gpg;
    int  require_fp, require_pm, n_fingerprints, changeme;
} stanza_info_t;

static char *
trim(char *s)
{
    char *e;
    while(*s == ' ' || *s == '\t') s++;
    e = s + strlen(s);
    while(e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t'))
        *--e = '\0';
    return s;
}

/* Parse access.conf into stanzas. Returns stanza count, or -1 on error. */
static int
parse_access_conf(const char *path, stanza_info_t *st, int max)
{
    FILE *fp = fopen(path, "r");
    char line[MAX_LINE];
    int n = -1, lineno = 0;
    char pending_name[128] = {0};
    int pending_name_line = 0;

    if(fp == NULL)
        return -1;

    while(fgets(line, sizeof(line), fp) != NULL)
    {
        char *p, *sp;
        char key[128] = {0}, val[512] = {0};

        lineno++;
        p = trim(line);

        if(strncmp(p, "### fwknopd-admin user:", 23) == 0)
        {
            strlcpy(pending_name, trim(p + 23), sizeof(pending_name));
            pending_name_line = lineno;
            continue;
        }
        if(*p == '\0' || *p == '#' || *p == '%')
            continue;

        sp = p;
        while(*sp && *sp != ' ' && *sp != '\t') sp++;
        if(*sp)
        {
            size_t klen = (size_t)(sp - p);
            if(klen >= sizeof(key)) klen = sizeof(key) - 1;
            memcpy(key, p, klen);
            key[klen] = '\0';
            strlcpy(val, trim(sp), sizeof(val));
        }
        else
            strlcpy(key, p, sizeof(key));

        if(strcmp(key, "SOURCE") == 0)
        {
            if(n >= 0)
                st[n].end_line = lineno - 1;
            if(++n >= max)
                break;
            memset(&st[n], 0, sizeof(st[n]));
            st[n].start_line = lineno;
            st[n].end_line = lineno;
            strlcpy(st[n].source, val, sizeof(st[n].source));
            strlcpy(st[n].name, pending_name, sizeof(st[n].name));
            st[n].name_line = pending_name_line;
            pending_name[0] = '\0';
            pending_name_line = 0;
            continue;
        }
        if(n < 0)
            continue;

        if(strstr(val, "__CHANGEME__") != NULL)
            st[n].changeme = 1;

        if(strcmp(key, "REQUIRE_USERNAME") == 0)
            strlcpy(st[n].require_username, val, sizeof(st[n].require_username));
        else if(strcmp(key, "OPEN_PORTS") == 0)
            strlcpy(st[n].open_ports, val, sizeof(st[n].open_ports));
        else if(strcmp(key, "FW_ACCESS_TIMEOUT") == 0)
            strlcpy(st[n].fw_access_timeout, val, sizeof(st[n].fw_access_timeout));
        else if(strcmp(key, "KEY_BASE64") == 0 || strcmp(key, "KEY") == 0)
        {
            st[n].has_key = 1;
            strlcpy(st[n].key_base64, val, sizeof(st[n].key_base64));
        }
        else if(strcmp(key, "HMAC_KEY_BASE64") == 0)
            strlcpy(st[n].hmac_key_base64, val, sizeof(st[n].hmac_key_base64));
        else if(strcmp(key, "GPG_DECRYPT_ID") == 0)
            st[n].has_gpg = 1;
        else if(strcmp(key, "TOTP_SEED_BASE64") == 0)
            strlcpy(st[n].totp_seed_base64, val, sizeof(st[n].totp_seed_base64));
        else if(strcmp(key, "TOTP_PORT_RANGE") == 0)
            strlcpy(st[n].port_range, val, sizeof(st[n].port_range));
        else if(strcmp(key, "REQUIRE_FINGERPRINT") == 0)
            st[n].require_fp = (toupper((unsigned char)val[0]) == 'Y');
        else if(strcmp(key, "FINGERPRINT") == 0)
            st[n].n_fingerprints++;
        else if(strcmp(key, "FINGERPRINT_TOFU_TIMEOUT") == 0)
            st[n].tofu_timeout = atoi(val);
        else if(strcmp(key, "REQUIRE_TOTP_PORT_MATCH") == 0)
            st[n].require_pm = (toupper((unsigned char)val[0]) == 'Y');
    }
    fclose(fp);

    if(n >= 0)
        st[n].end_line = lineno;
    return n + 1;
}

/* Display name of a stanza: marker name, else REQUIRE_USERNAME, else #N. */
static const char *
stanza_display_name(const stanza_info_t *s, int idx, char *buf, size_t bufsz)
{
    if(s->name[0])
        return s->name;
    if(s->require_username[0])
        return s->require_username;
    snprintf(buf, bufsz, "#%d", idx + 1);
    return buf;
}

static int
find_stanza(const stanza_info_t *st, int n, const char *name)
{
    int i;
    for(i = 0; i < n; i++)
        if((st[i].name[0] && strcmp(st[i].name, name) == 0)
                || (st[i].require_username[0]
                    && strcmp(st[i].require_username, name) == 0))
            return i;
    return -1;
}

/* Best-effort SIGHUP so fwknopd re-reads access.conf / TOFU state. */
static void
sighup_fwknopd(const char *pid_file)
{
    FILE *fp = fopen(pid_file, "r");
    long pid;
    if(fp == NULL)
    {
        printf("NOTE: pid file %s not readable; run 'kill -HUP <fwknopd pid>' "
               "manually to reload.\n", pid_file);
        return;
    }
    if(fscanf(fp, "%ld", &pid) == 1 && pid > 1)
    {
        if(kill((pid_t)pid, SIGHUP) == 0)
            printf("Sent SIGHUP to fwknopd (pid %ld) to reload config.\n", pid);
        else
            printf("NOTE: SIGHUP to pid %ld failed (%s); reload manually.\n",
                    pid, strerror(errno));
    }
    fclose(fp);
}

/* Copy src to dst (used for safety backups before edits). */
static int
backup_file(const char *src, char *dst, size_t dst_sz)
{
    FILE *in, *out;
    char buf[4096];
    size_t r;

    snprintf(dst, dst_sz, "%s.bak-%ld", src, (long)time(NULL));
    in = fopen(src, "r");
    if(in == NULL)
        return -1;
    out = fopen(dst, "w");
    if(out == NULL)
    { fclose(in); return -1; }
    while((r = fread(buf, 1, sizeof(buf), in)) > 0)
        fwrite(buf, 1, r, out);
    fclose(in);
    fclose(out);
    chmod(dst, 0600);
    return 0;
}

/* ------------------------------------------------------------------ */
/* fwknopd-admin user list [--access-conf F]                            */
/* ------------------------------------------------------------------ */
static int
cmd_user_list(const char *path)
{
    stanza_info_t st[MAX_STANZAS];
    int n, i;

    n = parse_access_conf(path, st, MAX_STANZAS);
    if(n < 0)
    {
        fprintf(stderr, "[*] cannot open %s: %s\n", path, strerror(errno));
        return EXIT_FAILURE;
    }
    if(n == 0)
    {
        printf("No stanzas found in %s.\n", path);
        return EXIT_SUCCESS;
    }

    printf("%s: %d stanza(s)\n\n", path, n);
    printf("%-3s %-16s %-10s %-12s %-14s %-4s %-5s %-5s %s\n",
            "#", "NAME", "SOURCE", "USER", "OPEN_PORTS",
            "KEY", "HMAC", "TOTP", "FINGERPRINT");
    for(i = 0; i < n; i++)
    {
        char dbuf[16], fpbuf[48];
        const char *dn = stanza_display_name(&st[i], i, dbuf, sizeof(dbuf));

        if(!st[i].require_fp)
            strlcpy(fpbuf, "-", sizeof(fpbuf));
        else if(st[i].n_fingerprints > 0)
            snprintf(fpbuf, sizeof(fpbuf), "whitelist(%d)", st[i].n_fingerprints);
        else
            snprintf(fpbuf, sizeof(fpbuf), "TOFU(%ds)",
                    st[i].tofu_timeout > 0 ? st[i].tofu_timeout : 86400);

        printf("%-3d %-16s %-10s %-12s %-14s %-4s %-5s %-5s %s%s\n",
                i + 1, dn,
                st[i].source[0] ? st[i].source : "-",
                st[i].require_username[0] ? st[i].require_username : "-",
                st[i].open_ports[0] ? st[i].open_ports : "(packet)",
                st[i].has_key || st[i].has_gpg ? "Y" : "N",
                st[i].hmac_key_base64[0] ? "Y" : "N",
                st[i].totp_seed_base64[0] ? "Y" : "N",
                fpbuf,
                st[i].changeme ? "  <-- __CHANGEME__ placeholder!" : "");
    }
    return EXIT_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* fwknopd-admin user rm <name> [--access-conf F] [--pid-file F]        */
/* Disables the stanza by commenting it out (reversible); backup first. */
/* ------------------------------------------------------------------ */
static int
cmd_user_rm(const char *name, const char *path, const char *pid_file)
{
    stanza_info_t st[MAX_STANZAS];
    char bak[MAX_PATH_LEN];
    char tmp[MAX_PATH_LEN];
    char line[MAX_LINE];
    char ts[32];
    FILE *in, *out;
    int n, idx, lineno = 0, disabled = 0;
    time_t now = time(NULL);

    n = parse_access_conf(path, st, MAX_STANZAS);
    if(n < 0)
    {
        fprintf(stderr, "[*] cannot open %s: %s\n", path, strerror(errno));
        return EXIT_FAILURE;
    }
    idx = find_stanza(st, n, name);
    if(idx < 0)
    {
        fprintf(stderr, "[*] no stanza matching '%s' in %s\n", name, path);
        return EXIT_FAILURE;
    }

    if(backup_file(path, bak, sizeof(bak)) != 0)
    {
        fprintf(stderr, "[*] backup of %s failed: %s\n", path, strerror(errno));
        return EXIT_FAILURE;
    }

    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    snprintf(tmp, sizeof(tmp), "%s.tmp-%ld", path, (long)getpid());

    /* Include the "### fwknopd-admin user:" marker line in the disabled
     * range so it is not re-attached to the following stanza. */
    if(st[idx].name_line > 0 && st[idx].name_line < st[idx].start_line)
        st[idx].start_line = st[idx].name_line;

    in = fopen(path, "r");
    out = fopen(tmp, "w");
    if(in == NULL || out == NULL)
    {
        fprintf(stderr, "[*] rewrite failed: %s\n", strerror(errno));
        if(in) fclose(in);
        if(out) fclose(out);
        unlink(tmp);
        return EXIT_FAILURE;
    }
    while(fgets(line, sizeof(line), in) != NULL)
    {
        lineno++;
        if(lineno >= st[idx].start_line && lineno <= st[idx].end_line)
        {
            char *p = trim(line);
            if(*p == '\0')
            { fputs(line, out); continue; }
            /* Ordinary comments pass through; the user-marker comment must
             * be neutralized so it is not re-attached to the next stanza. */
            if(*p == '#' && strncmp(p, "### fwknopd-admin user:", 23) != 0)
            { fputs(line, out); continue; }
            fprintf(out, "# [disabled by fwknopd-admin rm '%s' %s] %s\n",
                    name, ts, p);
            disabled++;
            continue;
        }
        fputs(line, out);
    }
    fclose(in);
    if(fclose(out) != 0 || rename(tmp, path) != 0)
    {
        fprintf(stderr, "[*] rename failed: %s (original kept, backup %s)\n",
                strerror(errno), bak);
        unlink(tmp);
        return EXIT_FAILURE;
    }
    chmod(path, 0600);

    printf("Disabled stanza '%s' (%d line(s) commented, lines %d-%d).\n",
            name, disabled, st[idx].start_line, st[idx].end_line);
    printf("Backup written to %s\n", bak);
    sighup_fwknopd(pid_file);
    return EXIT_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* fwknopd-admin user qr <name> --server H [--access-conf F]            */
/* Re-render the authorization URI/QR from an existing stanza.          */
/* ------------------------------------------------------------------ */
static int
cmd_user_qr(const char *name, const char *path, const char *server)
{
    stanza_info_t st[MAX_STANZAS];
    fwknop_credential_t c;
    char uri[1024];
    int n, idx;

    if(server == NULL || !server[0])
    {
        fprintf(stderr, "[*] --server H is required (access.conf does not "
                "record the SPA server address)\n");
        return EXIT_FAILURE;
    }
    n = parse_access_conf(path, st, MAX_STANZAS);
    if(n < 0)
    {
        fprintf(stderr, "[*] cannot open %s: %s\n", path, strerror(errno));
        return EXIT_FAILURE;
    }
    idx = find_stanza(st, n, name);
    if(idx < 0)
    {
        fprintf(stderr, "[*] no stanza matching '%s' in %s\n", name, path);
        return EXIT_FAILURE;
    }
    if(!st[idx].key_base64[0] || !st[idx].hmac_key_base64[0])
    {
        fprintf(stderr, "[*] stanza '%s' lacks KEY_BASE64/HMAC_KEY_BASE64; "
                "cannot rebuild URI (GPG stanzas unsupported)\n", name);
        return EXIT_FAILURE;
    }

    memset(&c, 0, sizeof(c));
    strlcpy(c.stanza, name, sizeof(c.stanza));
    strlcpy(c.spa_server, server, sizeof(c.spa_server));
    strlcpy(c.access, st[idx].open_ports[0] ? st[idx].open_ports : "tcp/22",
            sizeof(c.access));
    strlcpy(c.key_base64, st[idx].key_base64, sizeof(c.key_base64));
    strlcpy(c.hmac_key_base64, st[idx].hmac_key_base64, sizeof(c.hmac_key_base64));
    strlcpy(c.totp_seed_base64, st[idx].totp_seed_base64,
            sizeof(c.totp_seed_base64));
    strlcpy(c.port_range, st[idx].port_range[0] ? st[idx].port_range
            : DEFAULT_PORT_RANGE, sizeof(c.port_range));
    strlcpy(c.username, st[idx].require_username, sizeof(c.username));

    printf("----- fwknop:// authorization URI for '%s' -----\n", name);
    if(credential_to_uri(&c, uri, sizeof(uri)) < 0)
    {
        fprintf(stderr, "[*] URI build failed\n");
        memset(&c, 0, sizeof(c));
        return EXIT_FAILURE;
    }
    printf("%s\n\n", uri);
    render_qr(uri);
    memset(&c, 0, sizeof(c));
    memset(uri, 0, sizeof(uri));
    return EXIT_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* fwknopd-admin tofu unbind <stanza-key> <device_id> [--state-file F]  */
/* ------------------------------------------------------------------ */
static int
cmd_tofu_unbind(const char *key, const char *dev, const char *sf,
        const char *pid_file)
{
    char bak[MAX_PATH_LEN], tmp[MAX_PATH_LEN], line[MAX_LINE];
    char expect[MAX_LINE];
    FILE *in, *out;
    int removed = 0;

    in = fopen(sf, "r");
    if(in == NULL)
    {
        fprintf(stderr, "[*] cannot open %s: %s\n", sf, strerror(errno));
        return EXIT_FAILURE;
    }
    fclose(in);

    if(backup_file(sf, bak, sizeof(bak)) != 0)
    {
        fprintf(stderr, "[*] backup of %s failed: %s\n", sf, strerror(errno));
        return EXIT_FAILURE;
    }

    snprintf(expect, sizeof(expect), "%s %s", key, dev);
    snprintf(tmp, sizeof(tmp), "%s.tmp-%ld", sf, (long)getpid());

    in = fopen(sf, "r");
    out = fopen(tmp, "w");
    if(in == NULL || out == NULL)
    {
        fprintf(stderr, "[*] rewrite failed: %s\n", strerror(errno));
        if(in) fclose(in);
        if(out) fclose(out);
        unlink(tmp);
        return EXIT_FAILURE;
    }
    while(fgets(line, sizeof(line), in) != NULL)
    {
        if(strcmp(trim(line), expect) == 0)
        { removed++; continue; }
        fputs(line, out);
    }
    fclose(in);
    if(fclose(out) != 0 || rename(tmp, sf) != 0)
    {
        fprintf(stderr, "[*] rename failed: %s (backup %s)\n",
                strerror(errno), bak);
        unlink(tmp);
        return EXIT_FAILURE;
    }
    chmod(sf, 0600);

    if(removed == 0)
        printf("No binding matching '%s %s' in %s (backup %s).\n",
                key, dev, sf, bak);
    else
    {
        printf("Removed %d TOFU binding(s) for device %s (backup %s).\n",
                removed, dev, bak);
        printf("NOTE: fwknopd holds bindings in memory until reload.\n");
        sighup_fwknopd(pid_file);
    }
    return EXIT_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* fwknopd-admin lint [access.conf]                                     */
/* ------------------------------------------------------------------ */
static int
valid_port_range(const char *s)
{
    char *dash, *end;
    long a, b;
    if(s == NULL || !*s) return 0;
    a = strtol(s, &dash, 10);
    if(dash == s || *dash != '-') return 0;
    b = strtol(dash + 1, &end, 10);
    if(*end != '\0') return 0;
    return a >= 1 && a <= 65535 && b >= a && b <= 65535;
}

static int
valid_open_ports(const char *s)
{
    char buf[256], *tok, *save = NULL;
    if(!*s) return 1;   /* empty = honor the packet's request */
    strlcpy(buf, s, sizeof(buf));
    for(tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save))
    {
        char *slash, *end;
        long port;
        while(*tok == ' ') tok++;
        slash = strchr(tok, '/');
        if(slash == NULL) return 0;
        *slash = '\0';
        if(strcasecmp(tok, "tcp") != 0 && strcasecmp(tok, "udp") != 0)
            return 0;
        port = strtol(slash + 1, &end, 10);
        if(*end != '\0' || port < 1 || port > 65535) return 0;
    }
    return 1;
}

static int
cmd_lint(const char *path)
{
    stanza_info_t st[MAX_STANZAS];
    int n, i, errors = 0, warnings = 0;

    n = parse_access_conf(path, st, MAX_STANZAS);
    if(n < 0)
    {
        fprintf(stderr, "[*] cannot open %s: %s\n", path, strerror(errno));
        return EXIT_FAILURE;
    }
    printf("lint %s: %d stanza(s)\n", path, n);

    for(i = 0; i < n; i++)
    {
        char dbuf[16];
        const char *dn = stanza_display_name(&st[i], i, dbuf, sizeof(dbuf));

        if(!st[i].has_key && !st[i].has_gpg)
        { printf("  ERROR   [%s] no KEY_BASE64/KEY or GPG_DECRYPT_ID\n", dn); errors++; }
        if(st[i].has_key && !st[i].hmac_key_base64[0])
        { printf("  WARN    [%s] KEY_BASE64 without HMAC_KEY_BASE64 "
                 "(HMAC strongly recommended)\n", dn); warnings++; }
        if(st[i].changeme)
        { printf("  ERROR   [%s] still contains __CHANGEME__ placeholder\n", dn); errors++; }
        if(st[i].require_pm && !st[i].totp_seed_base64[0])
        { printf("  ERROR   [%s] REQUIRE_TOTP_PORT_MATCH without "
                 "TOTP_SEED_BASE64\n", dn); errors++; }
        if(st[i].totp_seed_base64[0] && st[i].port_range[0]
                && !valid_port_range(st[i].port_range))
        { printf("  ERROR   [%s] bad TOTP_PORT_RANGE '%s'\n",
                 dn, st[i].port_range); errors++; }
        if(st[i].totp_seed_base64[0] && !st[i].port_range[0])
        { printf("  WARN    [%s] TOTP_SEED_BASE64 without TOTP_PORT_RANGE "
                 "(client default %s must match)\n", dn, DEFAULT_PORT_RANGE);
          warnings++; }
        if(st[i].tofu_timeout > 0 && !st[i].require_fp)
        { printf("  WARN    [%s] FINGERPRINT_TOFU_TIMEOUT without "
                 "REQUIRE_FINGERPRINT\n", dn); warnings++; }
        if(st[i].require_fp && st[i].n_fingerprints == 0
                && st[i].tofu_timeout == 0)
            printf("  INFO    [%s] TOFU mode with default grace window "
                   "(86400s)\n", dn);
        if(!valid_open_ports(st[i].open_ports))
        { printf("  ERROR   [%s] bad OPEN_PORTS '%s'\n", dn, st[i].open_ports);
          errors++; }
    }

    printf("lint: %d error(s), %d warning(s)%s\n", errors, warnings,
            errors == 0 ? " — OK" : "");
    return errors ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* ------------------------------------------------------------------ */
static void
usage(void)
{
    fprintf(stderr,
        "fwknopd-admin - fwknop server administration (plan Sec.7.6)\n\n"
        "  fwknopd-admin user add <name> [--server H] [--access tcp/22]\n"
        "      [--user U] [--totp] [--port-range S-E] [--require-fingerprint]\n"
        "      [--tofu-timeout S] [--require-totp-port-match] [--no-qr]\n"
        "      [--export <file> [--plain]]\n"
        "      Generate keys/seed/fingerprint, print stanzas + QR + credential.\n"
        "  fwknopd-admin user list [--access-conf F]\n"
        "      List access.conf stanzas (keys masked).\n"
        "  fwknopd-admin user rm <name> [--access-conf F] [--pid-file F]\n"
        "      Disable a stanza (comments it out, backup first) + SIGHUP.\n"
        "  fwknopd-admin user qr <name> --server H [--access-conf F]\n"
        "      Re-render the authorization URI/QR for an existing stanza.\n"
        "  fwknopd-admin tofu list [--state-file F]\n"
        "  fwknopd-admin tofu unbind <stanza-key> <device_id> [--state-file F]\n"
        "      Remove a TOFU binding (backup first) + SIGHUP.\n"
        "  fwknopd-admin lint [access.conf]\n"
        "      Check stanza consistency (keys, TOTP, ports, placeholders).\n"
        "  fwknopd-admin status\n");
}

int
main(int argc, char **argv)
{
    if(argc < 2)
    {
        usage();
        return EXIT_FAILURE;
    }

    if(strcmp(argv[1], "user") == 0 && argc >= 3
            && strcmp(argv[2], "add") == 0 && argc >= 4)
    {
        fwknop_credential_t c;
        const char *name = argv[3];
        int use_totp = 1, require_fp = 1, require_pm = 0;
        int tofu_timeout = 0, no_qr = 0, i;
        const char *export_path = NULL;
        int plain = 0;

        memset(&c, 0, sizeof(c));
        strlcpy(c.stanza, name, sizeof(c.stanza));
        strlcpy(c.access, "tcp/22", sizeof(c.access));
        strlcpy(c.port_range, DEFAULT_PORT_RANGE, sizeof(c.port_range));

        for(i = 4; i < argc; i++)
        {
            if(strcmp(argv[i], "--server") == 0 && i+1 < argc)
                strlcpy(c.spa_server, argv[++i], sizeof(c.spa_server));
            else if(strcmp(argv[i], "--access") == 0 && i+1 < argc)
                strlcpy(c.access, argv[++i], sizeof(c.access));
            else if(strcmp(argv[i], "--user") == 0 && i+1 < argc)
                strlcpy(c.username, argv[++i], sizeof(c.username));
            else if(strcmp(argv[i], "--no-totp") == 0)
                use_totp = 0;
            else if(strcmp(argv[i], "--totp") == 0)
                use_totp = 1;
            else if(strcmp(argv[i], "--port-range") == 0 && i+1 < argc)
                strlcpy(c.port_range, argv[++i], sizeof(c.port_range));
            else if(strcmp(argv[i], "--no-require-fingerprint") == 0)
                require_fp = 0;
            else if(strcmp(argv[i], "--require-fingerprint") == 0)
                require_fp = 1;
            else if(strcmp(argv[i], "--tofu-timeout") == 0 && i+1 < argc)
                tofu_timeout = atoi(argv[++i]);
            else if(strcmp(argv[i], "--require-totp-port-match") == 0)
                require_pm = 1;
            else if(strcmp(argv[i], "--no-qr") == 0)
                no_qr = 1;
            else if(strcmp(argv[i], "--export") == 0 && i+1 < argc)
                export_path = argv[++i];
            else if(strcmp(argv[i], "--plain") == 0)
                plain = 1;
            else
            {
                fprintf(stderr, "[*] unknown option: %s\n", argv[i]);
                return EXIT_FAILURE;
            }
        }

        if(gen_material(&c, require_fp, use_totp) != 0)
            return EXIT_FAILURE;

        printf("=== fwknopd-admin: new credential '%s' ===\n\n", name);
        print_access_stanza(&c, require_fp, require_pm, tofu_timeout);

        printf("----- fwknop:// authorization URI -----\n");
        {
            char uri[1024];
            credential_to_uri(&c, uri, sizeof(uri));
            printf("%s\n\n", uri);
        }
        if(!no_qr)
        {
            char uri[1024];
            credential_to_uri(&c, uri, sizeof(uri));
            render_qr(uri);
            printf("\n");
        }

        if(export_path)
        {
            if(write_credential_file(&c, export_path, plain) != 0)
                return EXIT_FAILURE;
        }

        /* wipe sensitive buffers */
        memset(&c, 0, sizeof(c));
        return EXIT_SUCCESS;
    }

    if(strcmp(argv[1], "tofu") == 0 && argc >= 3
            && strcmp(argv[2], "list") == 0)
    {
        const char *sf = (argc >= 5 && strcmp(argv[3], "--state-file") == 0)
                         ? argv[4] : DEFAULT_TOFU_STATE;
        FILE *fp = fopen(sf, "r");
        char line[256];
        if(fp == NULL)
        {
            printf("No TOFU state file (%s).\n", sf);
            return EXIT_SUCCESS;
        }
        printf("TOFU bindings in %s:\n", sf);
        while(fgets(line, sizeof(line), fp) != NULL)
            printf("  %s", line);
        fclose(fp);
        return EXIT_SUCCESS;
    }

    if(strcmp(argv[1], "tofu") == 0 && argc >= 5
            && strcmp(argv[2], "unbind") == 0)
    {
        const char *sf = DEFAULT_TOFU_STATE;
        const char *pf = DEFAULT_PID_FILE;
        int i;
        for(i = 5; i < argc; i++)
        {
            if(strcmp(argv[i], "--state-file") == 0 && i+1 < argc)
                sf = argv[++i];
            else if(strcmp(argv[i], "--pid-file") == 0 && i+1 < argc)
                pf = argv[++i];
        }
        return cmd_tofu_unbind(argv[3], argv[4], sf, pf);
    }

    if(strcmp(argv[1], "user") == 0 && argc >= 3
            && strcmp(argv[2], "list") == 0)
    {
        const char *af = DEFAULT_ACCESS_CONF;
        int i;
        for(i = 3; i < argc; i++)
            if(strcmp(argv[i], "--access-conf") == 0 && i+1 < argc)
                af = argv[++i];
        return cmd_user_list(af);
    }

    if(strcmp(argv[1], "user") == 0 && argc >= 4
            && strcmp(argv[2], "rm") == 0)
    {
        const char *af = DEFAULT_ACCESS_CONF;
        const char *pf = DEFAULT_PID_FILE;
        int i;
        for(i = 4; i < argc; i++)
        {
            if(strcmp(argv[i], "--access-conf") == 0 && i+1 < argc)
                af = argv[++i];
            else if(strcmp(argv[i], "--pid-file") == 0 && i+1 < argc)
                pf = argv[++i];
        }
        return cmd_user_rm(argv[3], af, pf);
    }

    if(strcmp(argv[1], "user") == 0 && argc >= 4
            && strcmp(argv[2], "qr") == 0)
    {
        const char *af = DEFAULT_ACCESS_CONF;
        const char *server = NULL;
        int i;
        for(i = 4; i < argc; i++)
        {
            if(strcmp(argv[i], "--access-conf") == 0 && i+1 < argc)
                af = argv[++i];
            else if(strcmp(argv[i], "--server") == 0 && i+1 < argc)
                server = argv[++i];
        }
        return cmd_user_qr(argv[3], af, server);
    }

    if(strcmp(argv[1], "lint") == 0)
        return cmd_lint(argc >= 3 ? argv[2] : DEFAULT_ACCESS_CONF);

    if(strcmp(argv[1], "status") == 0)
    {
        printf("fwknopd-admin status:\n");
        printf("  protocol version: %s\n", FKO_PROTOCOL_VERSION);
        printf("  build: %s %s\n", __DATE__, __TIME__);
        return EXIT_SUCCESS;
    }

    usage();
    return EXIT_FAILURE;
}

/***EOF***/
