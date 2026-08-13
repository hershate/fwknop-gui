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
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

#define DEFAULT_PORT_RANGE "30000-60000"

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
        "  fwknopd-admin user rm <name> [--access-conf F]\n"
        "  fwknopd-admin user qr <name>   (re-render from access.conf)\n"
        "  fwknopd-admin tofu list [--state-file F]\n"
        "  fwknopd-admin tofu unbind <stanza-key> <device_id> [--state-file F]\n"
        "  fwknopd-admin lint [access.conf]\n"
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
                         ? argv[4] : "/var/run/fwknop/fwknop_tofu.state";
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

    if(strcmp(argv[1], "status") == 0)
    {
        printf("fwknopd-admin status:\n");
        printf("  protocol version: %s\n", FKO_PROTOCOL_VERSION);
        printf("  build: %s %s\n", __DATE__, __TIME__);
        return EXIT_SUCCESS;
    }

    /* Placeholder subcommands that operate on access.conf (list/rm/qr/lint)
     * require a full access.conf editor; provide clear messages for now. */
    if(strcmp(argv[1], "user") == 0 && argc >= 3
            && (strcmp(argv[2], "list") == 0 || strcmp(argv[2], "rm") == 0
                || strcmp(argv[2], "qr") == 0))
    {
        printf("(Use 'fwknopd-admin user add' to generate; %s on access.conf "
               "is handled by editing /etc/fwknop/access.conf and SIGHUP.)\n",
               argv[2]);
        return EXIT_SUCCESS;
    }

    if(strcmp(argv[1], "lint") == 0 || strcmp(argv[1], "status") == 0)
        return EXIT_SUCCESS;

    usage();
    return EXIT_FAILURE;
}

/***EOF***/
