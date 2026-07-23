/**
 * \file client/cli_subcmds.c
 *
 * \brief Friendly subcommand dispatch: `fwknop setup|knock|lint` (plan §7.1).
 *
 * These subcommands are thin, non-invasive conveniences layered on top of
 * the existing client.  `setup` runs an interactive wizard; `knock` is
 * rewritten into the normal send flow (`-n <profile> -R`); `lint` validates
 * the rc/access configuration.  Anything else falls through to classic
 * fwknop getopt behavior, so backward compatibility is preserved.
 */
#include "fwknop_common.h"
#include "fko.h"
#include "wizard.h"
#include "cli_subcmds.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* knock                                                              */
/* ------------------------------------------------------------------ */
/* Translate `fwknop knock [profile] [extra...]` into the equivalent
 * normal invocation `fwknop [-n <profile>] -R [extra...]` so the entire
 * existing send pipeline (TOTP port, external IP resolve, send) is reused.
 * The returned argv is heap-allocated and intentionally not freed (the
 * process exits shortly after). */
static int
knock_rewrite(int argc, char **argv, int *new_argc, char ***new_argv)
{
    char **na;
    int i, n = 0, have_profile = 0;

    na = calloc((size_t)argc + 4, sizeof(char *));
    if(na == NULL)
        return -1;

    na[n++] = argv[0];                 /* "fwknop" */

    if(argc >= 3 && argv[2][0] != '-')
    {
        na[n++] = "-n";
        na[n++] = argv[2];             /* profile name */
        have_profile = 1;
    }

    na[n++] = "-R";                    /* resolve the client's external IP */

    /* Copy any additional flags the user appended after the profile. */
    for(i = 2 + (have_profile ? 1 : 0); i < argc; i++)
        na[n++] = argv[i];

    *new_argc = n;
    *new_argv = na;
    return 0;
}

/* ------------------------------------------------------------------ */
/* lint                                                               */
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
    if(home == NULL)
        home = ".";
    snprintf(out, outlen, "%s%c.fwknoprc", home, PATH_SEP);
}

/* Lightweight fwknoprc validation.  Tracks stanzas and checks that each
 * carries the fields it promises (keys, server, TOTP seed, etc.).  Returns
 * the number of issues found. */
static int
lint_rc_file(const char *path)
{
    FILE *f = fopen(path, "r");
    char  line[MAX_LINE_LEN];
    int   issues = 0, stanza_open = 0;
    char  stanza[128] = {0};

    /* Per-stanza presence flags. */
    int has_server = 0, has_key = 0, has_hmac_key = 0, use_hmac = 0;
    int use_totp = 0, has_seed = 0, has_portrange = 0, has_device = 0;

    if(f == NULL)
    {
        fprintf(stderr, "lint: cannot open %s\n", path);
        return 1;
    }

#define LINT_FLUSH() do { \
        if(stanza_open) { \
            if(!has_server) { printf("  [%s] missing SPA_SERVER\n", stanza); issues++; } \
            if(!has_key)    { printf("  [%s] missing KEY_BASE64/KEY\n", stanza); issues++; } \
            if(use_hmac && !has_hmac_key) { printf("  [%s] USE_HMAC set but no HMAC_KEY_BASE64/HMAC_KEY\n", stanza); issues++; } \
            if(use_totp) { \
                if(!has_seed)      { printf("  [%s] USE_TOTP_PORT set but no TOTP_SEED_BASE64\n", stanza); issues++; } \
                if(!has_portrange) { printf("  [%s] USE_TOTP_PORT set but no PORT_RANGE\n", stanza); issues++; } \
            } \
            if(!has_device) printf("  [%s] note: no DEVICE_ID set\n", stanza); \
        } \
        has_server=0; has_key=0; has_hmac_key=0; use_hmac=0; \
        use_totp=0; has_seed=0; has_portrange=0; has_device=0; \
    } while(0)

    while(fgets(line, sizeof(line), f) != NULL)
    {
        char key[64], val[MAX_LINE_LEN];
        char *p, *v;

        val[0] = '\0';
        /* strip newline */
        line[strcspn(line, "\r\n")] = '\0';

        /* skip blank/comment lines */
        p = line;
        while(*p == ' ' || *p == '\t') p++;
        if(*p == '\0' || *p == '#') continue;

        if(*p == '[')
        {
            /* new stanza: flush previous */
            LINT_FLUSH();
            {
                char *close = strchr(p, ']');
                int   len   = close ? (int)(close - p - 1)
                                    : (int)strlen(p + 1);
                if(len >= (int)sizeof(stanza))
                    len = (int)sizeof(stanza) - 1;
                memcpy(stanza, p + 1, (size_t)len);
                stanza[len] = '\0';
            }
            stanza_open = 1;
            continue;
        }

        if(!stanza_open)
            continue;   /* settings outside a stanza are ignored here */

        /* split key/value on first whitespace */
        if(sscanf(p, "%63s %[^\n]", key, val) < 1)
            continue;
        v = val;

        if(strcmp(key, "SPA_SERVER") == 0)            has_server = 1;
        else if(strcmp(key, "KEY_BASE64") == 0)       { has_key = 1; }
        else if(strcmp(key, "KEY") == 0)              has_key = 1;
        else if(strcmp(key, "HMAC_KEY_BASE64") == 0)  has_hmac_key = 1;
        else if(strcmp(key, "HMAC_KEY") == 0)         has_hmac_key = 1;
        else if(strcmp(key, "USE_HMAC") == 0)         use_hmac = (v[0]=='y' || v[0]=='Y');
        else if(strcmp(key, "USE_TOTP_PORT") == 0)    use_totp = (v[0]=='y' || v[0]=='Y');
        else if(strcmp(key, "TOTP_SEED_BASE64") == 0) has_seed = (v[0] != '\0');
        else if(strcmp(key, "PORT_RANGE") == 0)       has_portrange = (strchr(v, '-') != NULL);
        else if(strcmp(key, "DEVICE_ID") == 0)        has_device = (v[0] != '\0');
    }

    LINT_FLUSH();
#undef LINT_FLUSH
    fclose(f);
    return issues;
}

static int
cli_lint(int argc, char **argv)
{
    const char *rcpath = NULL, *accpath = NULL;
    char        defrc[MAX_PATH_LEN];
    int         i, issues = 0;

    for(i = 2; i < argc; i++)
    {
        if(strcmp(argv[i], "--access-conf") == 0 && i + 1 < argc)
            accpath = argv[++i];
        else if(strncmp(argv[i], "--access-conf=", 14) == 0)
            accpath = argv[i] + 14;
        else if(argv[i][0] != '-')
            rcpath = argv[i];
    }

    if(rcpath == NULL)
    {
        default_rc_path(defrc, sizeof(defrc));
        rcpath = defrc;
    }

    printf("lint: checking %s\n", rcpath);
    issues += lint_rc_file(rcpath);

    if(accpath != NULL)
    {
        printf("lint: NOTE server-side access.conf validation (%s) requires\n", accpath);
        printf("      cross-checking against fwknopd stanzas (Phase 4 server work).\n");
    }

    if(issues == 0)
    {
        printf("lint: OK, no issues found.\n");
        return EXIT_SUCCESS;
    }
    printf("lint: %d issue(s) found.\n", issues);
    return EXIT_FAILURE;
}

/* ------------------------------------------------------------------ */
int
cli_handle_subcommand(int argc, char **argv, int *new_argc, char ***new_argv)
{
    if(argc < 2 || argv[1] == NULL)
        return CLI_SUB_NONE;

    if(strcmp(argv[1], "setup") == 0)
    {
        exit(wizard_setup());
    }
    if(strcmp(argv[1], "lint") == 0)
    {
        exit(cli_lint(argc, argv));
    }
    if(strcmp(argv[1], "knock") == 0)
    {
        if(knock_rewrite(argc, argv, new_argc, new_argv) != 0)
        {
            fprintf(stderr, "knock: internal error\n");
            exit(EXIT_FAILURE);
        }
        return CLI_SUB_KNOCK;
    }
    return CLI_SUB_NONE;
}

/***EOF***/
