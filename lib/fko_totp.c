/**
 * \file lib/fko_totp.c
 *
 * \brief TOTP (RFC 6238) generation for the port-hopping SPA feature.
 *
 * This implements the time-based one-time password algorithm from RFC 6238
 * using HMAC-SHA256 (reusing lib/hmac.c). The resulting decimal code is the
 * shared, time-varying value that both client and server independently map to
 * a destination port (see fko_totp_to_port in common/fko_util.c). This keeps
 * fwknop's single-packet SPA model intact: the SPA payload is unchanged, only
 * the destination port hops over time, so there is no fixed listening port for
 * scanners to find.
 */

/*
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *****************************************************************************
*/
#include "fko_common.h"
#include "fko.h"
#include "fko_totp.h"
#include "hmac.h"
#include "fko_util.h"

/* SHA-256 produces a 32-byte digest; this is the only HMAC variant TOTP uses.
*/
#define TOTP_HMAC_LEN 32

/* Apply the RFC 4226 dynamic-truncation step to the HMAC result and reduce it
 * modulo 10^digits to obtain the decimal code value.
*/
static unsigned long long
totp_truncate(const unsigned char *mac, const int mac_len, const unsigned char digits)
{
    int               offset;
    unsigned int      bin;
    unsigned long long mod = 1;
    int               i;

    /* Take the low nibble of the last byte as the offset into the MAC.
    */
    offset = mac[mac_len - 1] & 0x0f;

    /* Extract a 31-bit big-endian integer starting at offset (mask the high
     * bit so the value is always positive, per RFC 4226).
    */
    bin = ((mac[offset]     & 0x7f) << 24)
        | ((mac[offset + 1] & 0xff) << 16)
        | ((mac[offset + 2] & 0xff) << 8)
        | (mac[offset + 3] & 0xff);

    for(i=0; i < digits; i++)
        mod *= 10ULL;

    return (unsigned long long)bin % mod;
}

/* Generate a TOTP code (RFC 6238, HMAC-SHA256) for the given unix time.
*/
int
fko_totp_generate(const unsigned char *seed, const int seed_len,
        const time_t unix_time, const unsigned char digits,
        char *out_code)
{
    unsigned char     ctr[8];
    unsigned char     mac[TOTP_HMAC_LEN];
    unsigned long long counter;
    unsigned long long code;
    int               i, res;

    if(seed == NULL || seed_len <= 0 || out_code == NULL)
        return(FKO_ERROR_INVALID_DATA);

    if(digits < FKO_TOTP_MIN_DIGITS || digits > FKO_TOTP_MAX_DIGITS)
        return(FKO_ERROR_INVALID_DATA);

    /* T = floor((unix_time - T0) / step); counter is encoded as a 64-bit
     * big-endian integer (the HMAC message), independent of host endianness.
    */
    counter = (unsigned long long)(unix_time - FKO_TOTP_T0)
        / (unsigned long long)FKO_TOTP_DEFAULT_STEP;

    for(i=7; i >= 0; i--)
    {
        ctr[i] = (unsigned char)(counter & 0xff);
        counter >>= 8;
    }

    res = hmac_sha256((const char *)ctr, 8, mac,
            (const char *)seed, seed_len);
    if(res != FKO_SUCCESS)
        return(res);

    code = totp_truncate(mac, TOTP_HMAC_LEN, digits);

    /* Zero-pad to the requested number of digits.
    */
    snprintf(out_code, digits + 1, "%0*llu", (int)digits, code);

    /* Clear sensitive intermediate state.
    */
    memset(mac, 0x0, sizeof(mac));
    memset(ctr, 0x0, sizeof(ctr));

    return(FKO_SUCCESS);
}

/* Generate the current TOTP code and map it to a port in [port_start,port_end].
*/
int
fko_totp_port_now(const unsigned char *seed, const int seed_len,
        const time_t unix_time, const unsigned char digits,
        const unsigned int port_start, const unsigned int port_end,
        unsigned int *port_out)
{
    char  code[FKO_TOTP_CODE_LEN];
    int   res;

    if(port_out == NULL)
        return(FKO_ERROR_INVALID_DATA);

    res = fko_totp_generate(seed, seed_len, unix_time, digits, code);
    if(res != FKO_SUCCESS)
        return(res);

    *port_out = fko_totp_to_port(code, port_start, port_end);
    if(*port_out == 0)
        return(FKO_ERROR_INVALID_DATA);

    return(FKO_SUCCESS);
}

/***EOF***/
