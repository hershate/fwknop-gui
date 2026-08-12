/**
 * \file server/credential.h
 *
 * \brief fwknop credential file (JSON v1) + fwknop:// URI helpers.
 *
 * Shared by fwknopd-admin (issuer) and fwknop import (client). The credential
 * carries the full bearer material (Rijndael + HMAC + TOTP seed + port range)
 * so importing it produces a ready-to-use client stanza. Encryption defaults
 * to on (fko_encrypt_buf, AES-256-CBC + passphrase); --plain emits cleartext.
 * See REF/plan/Port Knocking.md §7.6 / appendix E.
 */
#ifndef CREDENTIAL_H
#define CREDENTIAL_H

#include "fwknopd_common.h"

/* Maximum sizes for the credential fields. */
#define CRED_FIELD_LEN   256
#define CRED_JSON_MAX    2048

/* A parsed credential. Strings are base64 (as carried in fwknoprc/access.conf). */
typedef struct {
    char     stanza[CRED_FIELD_LEN];
    char     spa_server[CRED_FIELD_LEN];
    char     access[CRED_FIELD_LEN];
    char     key_base64[CRED_FIELD_LEN];
    char     hmac_key_base64[CRED_FIELD_LEN];
    char     totp_seed_base64[CRED_FIELD_LEN];
    char     port_range[CRED_FIELD_LEN];
    char     device_id[CRED_FIELD_LEN];
    char     username[CRED_FIELD_LEN];
} fwknop_credential_t;

/**
 * \brief Serialize a credential to a JSON v1 string.
 * \return bytes written to out, or <0 on error.
 */
int credential_to_json(const fwknop_credential_t *c, char *out, size_t out_sz);

/**
 * \brief Parse a JSON v1 credential string into a credential struct.
 * \return 0 on success, <0 on error.
 */
int credential_from_json(const char *json, fwknop_credential_t *c);

/**
 * \brief Build a fwknop:// authorization URI from a credential.
 * \return bytes written to out, or <0 on error.
 */
int credential_to_uri(const fwknop_credential_t *c, char *out, size_t out_sz);

/**
 * \brief Parse a fwknop:// URI into a credential struct.
 * \return 0 on success, <0 on error.
 */
int credential_from_uri(const char *uri, fwknop_credential_t *c);

#endif /* CREDENTIAL_H */

/***EOF***/
