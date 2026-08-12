/**
 * \file client/import.h
 *
 * \brief `fwknop import` — load a credential (QR/URI/JSON file) into a
 *        fwknoprc stanza (plan §7.6.3). Server-issued credentials become a
 *        ready-to-use client profile.
 */
#ifndef FKO_IMPORT_H
#define FKO_IMPORT_H 1

/**
 * Run `fwknop import <qr.png|uri|cred.json> [--name N] [--rc-file F]
 * [--passphrase ...]`. Reads the credential, decrypts if needed, and appends
 * a stanza to the rc file (default ~/.fwknoprc). Returns EXIT_SUCCESS/FAILURE.
 */
int cli_import(int argc, char **argv);

#endif /* FKO_IMPORT_H */

/***EOF***/
