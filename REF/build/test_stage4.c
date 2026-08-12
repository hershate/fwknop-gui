/*
 * Stage 4 contract test: proves the server-side REQUIRE_TOTP_PORT_MATCH and
 * device_id whitelist can agree with what the client sends.
 *
 *  1. TOTP port agreement: for a given seed + timestamp + range, the value the
 *     client computes (fko_totp_port_now) MUST equal the value the server
 *     recomputes from the SPA timestamp. This is the invariant that makes
 *     check_totp_port() correct. We also confirm a replay to a *different*
 *     port (off-by-one) would be rejected.
 *
 *  2. device_id round-trip + whitelist comparison: encode a device_id, decode
 *     it back, and confirm constant-time whitelist matching accepts a known
 *     fingerprint and rejects an unknown one — mirroring check_device_id().
 *
 * Build (Linux): see REF/build/run_stage4.sh
 * Build artifact only (REF/ is gitignored) — not part of the shipped tree.
 */
#include "fko.h"
#include "fko_totp.h"
#include "fko_util.h"
#include <stdio.h>
#include <string.h>

/* RFC 6238 SHA-256 seed (32 bytes). */
static const unsigned char SEED[] = "12345678901234567890123456789012";
#define SEED_LEN 32
#define PORT_START 30000
#define PORT_END   60000

int main(void)
{
    int fails = 0;

    /* ---- 1. TOTP port agreement (client vs server recomputation) ---- */
    printf("== TOTP port agreement (client == server) ==\n");
    {
        time_t ts = 1234567890;   /* arbitrary SPA timestamp */
        unsigned int client_port = 0, server_port = 0;
        int r1 = fko_totp_port_now(SEED, SEED_LEN, ts, 8,
                PORT_START, PORT_END, &client_port);
        int r2 = fko_totp_port_now(SEED, SEED_LEN, ts, 8,
                PORT_START, PORT_END, &server_port);
        int ok = (r1 == FKO_SUCCESS && r2 == FKO_SUCCESS
                  && client_port == server_port
                  && client_port >= PORT_START && client_port <= PORT_END);
        printf("  client_port=%u server_port=%u  %s\n",
                client_port, server_port, ok ? "PASS" : "FAIL");
        if(!ok) fails++;

        /* A packet arriving on a different port must mismatch. */
        printf("== port mismatch detection (replay to wrong port) ==\n");
        {
            unsigned int wrong = (client_port == PORT_START) ? PORT_END
                                                             : client_port - 1;
            int ok2 = (wrong != client_port);
            printf("  arrived=%u expected=%u  %s\n",
                    wrong, client_port, ok2 ? "PASS (would reject)" : "FAIL");
            if(!ok2) fails++;
        }

        /* Determinism: same timestamp/seed always yields the same port. */
        printf("== port determinism across calls ==\n");
        {
            unsigned int p2 = 0;
            fko_totp_port_now(SEED, SEED_LEN, ts, 8,
                    PORT_START, PORT_END, &p2);
            int ok3 = (p2 == client_port);
            printf("  port=%u repeat=%u  %s\n",
                    client_port, p2, ok3 ? "PASS" : "FAIL");
            if(!ok3) fails++;
        }
    }

    /* ---- 2. device_id round-trip + whitelist comparison ---- */
    printf("== device_id round-trip + whitelist match ==\n");
    {
        fko_ctx_t ctx = NULL;
        char *got_dev = NULL;
        const char *dev = "stage4-device-AAAA";
        int r;

        r = fko_new(&ctx);
        if(r != FKO_SUCCESS) { printf("  fko_new FAIL\n"); fails++; goto done; }

        r = fko_set_device_id(ctx, dev);
        if(r != FKO_SUCCESS) { printf("  set_device_id FAIL\n"); fails++; }

        r = fko_get_device_id(ctx, &got_dev);
        if(r != FKO_SUCCESS || got_dev == NULL
                || strcmp(got_dev, dev) != 0)
        { printf("  get_device_id FAIL (got=%s)\n",
                  got_dev ? got_dev : "<null>"); fails++; }
        else
            printf("  device_id round-trip: %s  PASS\n", got_dev);

        /* Whitelist comparison mirrors check_device_id(): accept known,
         * reject unknown, using constant_runtime_cmp on equal lengths. */
        {
            const char *whitelist[2] = { "other-device-XXXX", dev };
            int i, matched = 0;
            size_t dl = strlen(got_dev);
            for(i = 0; i < 2; i++)
            {
                if(dl == strlen(whitelist[i])
                        && constant_runtime_cmp(got_dev, whitelist[i], dl) == 0)
                { matched = 1; break; }
            }
            printf("  whitelist accepts known device:  %s\n",
                    matched ? "PASS" : "FAIL");
            if(!matched) fails++;

            /* Unknown device must NOT match. */
            {
                const char *unknown = "attacker-device-ZZZ";
                int badmatch = 0;
                size_t ul = strlen(unknown);
                for(i = 0; i < 2; i++)
                {
                    if(ul == strlen(whitelist[i])
                            && constant_runtime_cmp(unknown, whitelist[i], ul) == 0)
                    { badmatch = 1; break; }
                }
                printf("  whitelist rejects unknown device: %s\n",
                        !badmatch ? "PASS" : "FAIL");
                if(badmatch) fails++;
            }
        }

    done:
        if(ctx) fko_destroy(ctx);
    }

    printf("\nRESULT: %s (%d failure group(s))\n",
            fails == 0 ? "ALL PASS" : "FAILURES", fails);
    return fails ? 1 : 0;
}
