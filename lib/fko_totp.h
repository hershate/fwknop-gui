/**
 * \file lib/fko_totp.h
 *
 * \brief TOTP (RFC 6238) support for the port-hopping SPA feature.
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
#ifndef FKO_TOTP_H
#define FKO_TOTP_H 1

#include "fko.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Defaults follow RFC 6238. The time step is 30 seconds; we default to an
 * 8-digit code so the value can cover a wide port range without collisions.
*/
#define FKO_TOTP_DEFAULT_STEP     30   /**< Time step in seconds          */
#define FKO_TOTP_T0               0    /**< Unix epoch start time         */
#define FKO_TOTP_DEFAULT_DIGITS   8    /**< Default code length           */
#define FKO_TOTP_MIN_DIGITS       6    /**< Minimum code length           */
#define FKO_TOTP_MAX_DIGITS      10    /**< Maximum code length           */
#define FKO_TOTP_CODE_LEN  (FKO_TOTP_MAX_DIGITS + 1) /**< NUL-terminated buffer */

/**
 * \brief Generate a TOTP code (RFC 6238, HMAC-SHA256) for a given time.
 *
 * The shared secret is taken as raw bytes; callers that store the seed
 * base64-encoded should decode it before calling (see fko_base64_decode).
 *
 * \param seed      Raw shared secret
 * \param seed_len  Length of seed in bytes
 * \param unix_time Current time in seconds since the epoch
 * \param digits    Code length (FKO_TOTP_MIN_DIGITS..FKO_TOTP_MAX_DIGITS)
 * \param out_code  Output buffer of at least (digits + 1) bytes
 *
 * \return FKO_SUCCESS on success, an error code otherwise.
 */
int fko_totp_generate(const unsigned char *seed, const int seed_len,
        const time_t unix_time, const unsigned char digits,
        char *out_code);

/**
 * \brief Generate the current TOTP code and map it to a destination port.
 *
 * Combines fko_totp_generate() with fko_totp_to_port() (common/fko_util.c)
 * to produce the port-hopping SPA destination port for the given time.
 *
 * \return FKO_SUCCESS on success (port written to *port_out), error otherwise.
 */
int fko_totp_port_now(const unsigned char *seed, const int seed_len,
        const time_t unix_time, const unsigned char digits,
        const unsigned int port_start, const unsigned int port_end,
        unsigned int *port_out);

#ifdef __cplusplus
}
#endif

#endif /* FKO_TOTP_H */

/***EOF***/
