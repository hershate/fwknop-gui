/**
 * \file lib/fko_cred.c
 *
 * \brief Exported passphrase-based encrypt/decrypt for arbitrary buffers.
 *
 * Used by fwknopd-admin / fwknop import to protect credential files. Wraps
 * the proven libfko Rijndael (AES-256-CBC) path: a passphrase is used as the
 * key material and rij_encrypt() generates a random salt and derives the
 * key+IV via the OpenSSL-compatible MD5 KDF, emitting "Salted__<salt><ct>".
 * The result is base64-encoded so credential files stay text.
 *
 * This is NOT a new crypto primitive — it reuses cipher_funcs.c exactly as
 * fko_encryption.c does for SPA payloads (REF/plan/Port Knocking.md §7.6.4).
 */
#include "fko_common.h"
#include "fko.h"
#include "cipher_funcs.h"
#include "base64.h"

/**
 * \brief Encrypt a buffer with a passphrase (AES-256-CBC, OpenSSL-compatible).
 *
 * \param pass      Passphrase (used as key material)
 * \param pass_len  Length of passphrase
 * \param in        Plaintext to encrypt
 * \param in_len    Length of in
 * \param out_b64   Output buffer for base64("Salted__"+salt+ciphertext)
 * \param out_b64_len  Size of out_b64 (recommend in_len*2 + 64)
 *
 * \return bytes written to out_b64 (NUL-terminated), or <0 on error.
 */
int
fko_encrypt_buf(const char *pass, const int pass_len,
        const unsigned char *in, const int in_len,
        char *out_b64, const int out_b64_len)
{
    unsigned char *cipher = NULL;
    int            cipher_len = 0;
    int            b64_len = 0;

    if(pass == NULL || pass_len <= 0 || in == NULL || in_len <= 0
            || out_b64 == NULL || out_b64_len <= 0)
        return -1;

    cipher = malloc(PREDICT_ENCSIZE(in_len));
    if(cipher == NULL)
        return -2;

    cipher_len = (int)rij_encrypt((unsigned char *)in, (size_t)in_len,
            pass, pass_len, cipher, FKO_ENC_MODE_CBC);

    b64_len = fko_base64_encode(cipher, out_b64, cipher_len);

    memset(cipher, 0, cipher_len);
    free(cipher);
    return b64_len;
}

/**
 * \brief Decrypt a base64("Salted__"+salt+ciphertext) buffer with a passphrase.
 *
 * \param pass      Passphrase
 * \param pass_len  Length of passphrase
 * \param in_b64    Base64 ciphertext (as produced by fko_encrypt_buf)
 * \param out       Output buffer for plaintext
 * \param out_len   Size of out
 *
 * \return plaintext length, or <0 on error.
 */
int
fko_decrypt_buf(const char *pass, const int pass_len,
        const char *in_b64, unsigned char *out, const int out_len)
{
    unsigned char *cipher = NULL;
    int            cipher_len = 0;
    int            pt_len = 0;

    if(pass == NULL || pass_len <= 0 || in_b64 == NULL || out == NULL
            || out_len <= 0)
        return -1;

    cipher = malloc(strlen(in_b64) + 1);
    if(cipher == NULL)
        return -2;

    cipher_len = fko_base64_decode(in_b64, cipher);
    if(cipher_len <= 0)
    {
        free(cipher);
        return -3;
    }

    pt_len = (int)rij_decrypt(cipher, (size_t)cipher_len,
            pass, pass_len, out, FKO_ENC_MODE_CBC);

    memset(cipher, 0, cipher_len);
    free(cipher);
    return pt_len;
}

/***EOF***/
