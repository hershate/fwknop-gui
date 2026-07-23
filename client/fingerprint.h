/**
 * \file client/fingerprint.h
 *
 * \brief Device fingerprint generation (plan Appendix C).
 */
#ifndef FKO_FINGERPRINT_H
#define FKO_FINGERPRINT_H 1

/*
 * Generate a stable, per-device fingerprint as a base64 string
 * (SHA-256 of canonicalized host attributes, first 16 bytes, base64).
 * Used as the SPA v4 device_id value.  Only the hashed digest ever
 * leaves the host -- no plaintext hardware attributes are transmitted.
 *
 * \param out_b64  Output buffer for the base64 fingerprint.
 * \param out_b64_len  Size of out_b64 (recommend >= 32).
 * \return 0 on success, -1 on error.
 */
int gen_device_fingerprint(char *out_b64, const int out_b64_len);

#endif /* FKO_FINGERPRINT_H */

/***EOF***/
