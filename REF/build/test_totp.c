/*
 * Standalone unit test for the fwknop TOTP engine + port mapping.
 * Validates against the official RFC 6238 Appendix B SHA-256 test vectors.
 * Build artifact only (REF/ is gitignored) — not part of the shipped tree.
 */
#include "fko.h"
#include "fko_totp.h"
#include "fko_util.h"
#include <stdio.h>
#include <string.h>

struct vec { time_t t; const char *expect; };

int main(void)
{
    /* RFC 6238 SHA-256 seed: "12345678901234567890123456789012" (32 bytes). */
    const unsigned char seed[] = "12345678901234567890123456789012";
    const int           seed_len = 32;
    struct vec v[6] = {
        {          59, "46119246"},
        {  1111111109, "68084774"},
        {  1111111111, "67062674"},
        {  1234567890, "91819424"},
        {  2000000000, "90698825"},
        { 20000000000LL, "77737706"}
    };
    char code[FKO_TOTP_CODE_LEN];
    int  i, fails = 0;

    printf("== TOTP RFC 6238 (HMAC-SHA256, 8 digits) ==\n");
    for(i=0; i<6; i++)
    {
        int res = fko_totp_generate(seed, seed_len, v[i].t, 8, code);
        int ok  = (res == FKO_SUCCESS && strcmp(code, v[i].expect) == 0);
        printf("  T=%-11lld expect=%s got=%-10s %s\n",
                (long long)v[i].t, v[i].expect,
                (res == FKO_SUCCESS) ? code : "<ERR>",
                ok ? "PASS" : "FAIL");
        if(!ok) fails++;
    }

    printf("== port mapping (determinism + bounds) ==\n");
    {
        unsigned int p1  = fko_totp_to_port("46119246", 30000, 60000);
        unsigned int p2  = fko_totp_to_port("46119246", 30000, 60000);
        unsigned int p3  = fko_totp_to_port("68084774", 30000, 60000);
        unsigned int pin = fko_totp_to_port("46119246", 30000, 30000);
        unsigned int bad = fko_totp_to_port("46119246", 60000, 30000); /* inverted */
        int ok = (p1 == p2 && p1 >= 30000 && p1 <= 60000
                  && p3 >= 30000 && p3 <= 60000
                  && pin == 30000 && bad == 0);
        printf("  port(46119246)=%u (repeat=%u)  port(68084774)=%u  "
               "single=%u  inverted=%u  %s\n",
               p1, p2, p3, pin, bad, ok ? "PASS" : "FAIL");
        if(!ok) fails++;
    }

    printf("== fko_totp_port_now convenience ==\n");
    {
        unsigned int port = 0, expect;
        int res = fko_totp_port_now(seed, seed_len, 59, 8, 30000, 60000, &port);
        expect = fko_totp_to_port("46119246", 30000, 60000);
        int ok = (res == FKO_SUCCESS && port == expect);
        printf("  port_now(T=59)=%u expect=%u  %s\n",
               port, expect, ok ? "PASS" : "FAIL");
        if(!ok) fails++;
    }

    printf("\nRESULT: %s (%d failure group(s))\n",
            fails == 0 ? "ALL PASS" : "FAILURES", fails);
    return fails ? 1 : 0;
}
