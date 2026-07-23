/**
 * \file client/wizard.h
 *
 * \brief Interactive `fwknop setup` wizard (plan §7.1).
 */
#ifndef FKO_WIZARD_H
#define FKO_WIZARD_H 1

/*
 * Run the interactive setup wizard: collect target/identity/port info,
 * generate Rijndael + HMAC keys, a TOTP seed, and a device fingerprint,
 * then print (and optionally write) the matching client fwknoprc stanza,
 * server access.conf stanza, and an otpauth:// URI.
 *
 * \return process exit code (0 on success).
 */
int wizard_setup(void);

#endif /* FKO_WIZARD_H */

/***EOF***/
