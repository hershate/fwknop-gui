/**
 * \file server/credential.c
 *
 * \brief fwknop credential file (JSON v1) + fwknop:// URI serialization.
 *
 * Minimal, dependency-free JSON value extraction: the credential format is
 * fixed and flat (string fields only), so a tiny "find \"key\":\"value\"" reader
 * is sufficient and avoids pulling in a JSON library. The fwknop:// URI uses
 * URL-safe base64 (no padding) for the secret fields.
 */
#include "fwknopd_common.h"
#include "credential.h"
#include "fko.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* tiny JSON field extractor: finds "key":"value" and copies value      */
/* (unescaping \" and \\) into out. Returns 1 if found, 0 otherwise.    */
/* ------------------------------------------------------------------ */
static int
json_get_str(const char *json, const char *key, char *out, size_t out_sz)
{
    char needle[64];
    const char *p, *q;
    size_t i = 0;

    snprintf(needle, sizeof(needle), "\"%s\"", key);
    p = strstr(json, needle);
    if(p == NULL)
        return 0;
    p += strlen(needle);
    /* skip whitespace and the colon */
    while(*p && (*p == ' ' || *p == '\t' || *p == ':'))
        p++;
    if(*p != '"')
        return 0;
    p++;
    q = p;
    while(*q && *q != '"' && i + 1 < out_sz)
    {
        if(*q == '\\' && (q[1] == '"' || q[1] == '\\'))
            q++;
        out[i++] = *q++;
    }
    out[i] = '\0';
    return 1;
}

int
credential_to_json(const fwknop_credential_t *c, char *out, size_t out_sz)
{
    int n;
    if(c == NULL || out == NULL)
        return -1;
    n = snprintf(out, out_sz,
        "{\"fmt\":\"fwknop-credential\",\"version\":1,"
        "\"stanza\":\"%s\",\"spa_server\":\"%s\",\"access\":\"%s\","
        "\"key_base64\":\"%s\",\"hmac_key_base64\":\"%s\","
        "\"totp_seed_base64\":\"%s\",\"port_range\":\"%s\","
        "\"device_id\":\"%s\",\"username\":\"%s\"}",
        c->stanza, c->spa_server, c->access,
        c->key_base64, c->hmac_key_base64,
        c->totp_seed_base64, c->port_range,
        c->device_id, c->username);
    return n;
}

int
credential_from_json(const char *json, fwknop_credential_t *c)
{
    if(json == NULL || c == NULL)
        return -1;
    memset(c, 0, sizeof(*c));
    json_get_str(json, "stanza",        c->stanza,        sizeof(c->stanza));
    json_get_str(json, "spa_server",    c->spa_server,    sizeof(c->spa_server));
    json_get_str(json, "access",        c->access,        sizeof(c->access));
    json_get_str(json, "key_base64",    c->key_base64,    sizeof(c->key_base64));
    json_get_str(json, "hmac_key_base64", c->hmac_key_base64, sizeof(c->hmac_key_base64));
    json_get_str(json, "totp_seed_base64", c->totp_seed_base64, sizeof(c->totp_seed_base64));
    json_get_str(json, "port_range",    c->port_range,    sizeof(c->port_range));
    json_get_str(json, "device_id",     c->device_id,     sizeof(c->device_id));
    json_get_str(json, "username",      c->username,      sizeof(c->username));
    /* require the two essential crypto fields */
    if(c->key_base64[0] == '\0' || c->hmac_key_base64[0] == '\0')
        return -2;
    return 0;
}

/* ------------------------------------------------------------------ */
/* URL-safe base64 helpers (for URI fields): + -> -, / -> _, strip =    */
/* ------------------------------------------------------------------ */
static void
b64_to_urlsafe(char *s)
{
    for(; *s; s++)
    {
        if(*s == '+') *s = '-';
        else if(*s == '/') *s = '_';
    }
    /* strip padding */
    {
        size_t n = strlen(s);
        while(n > 0 && s[n-1] == '=')
            s[--n] = '\0';
    }
}

static void
b64_from_urlsafe(char *s)
{
    /* restore padding based on length mod 4 */
    size_t n = strlen(s);
    size_t pad = (4 - (n % 4)) % 4;
    for(; *s; s++)
    {
        if(*s == '-') *s = '+';
        else if(*s == '_') *s = '/';
    }
    if(pad > 0)
    {
        char *end = s + n;
        while(pad-- > 0)
            *end++ = '=';
        *end = '\0';
    }
}

int
credential_to_uri(const fwknop_credential_t *c, char *out, size_t out_sz)
{
    char k[CRED_FIELD_LEN], h[CRED_FIELD_LEN], t[CRED_FIELD_LEN];
    if(c == NULL || out == NULL)
        return -1;
    strlcpy(k, c->key_base64, sizeof(k));      b64_to_urlsafe(k);
    strlcpy(h, c->hmac_key_base64, sizeof(h)); b64_to_urlsafe(h);
    strlcpy(t, c->totp_seed_base64, sizeof(t)); b64_to_urlsafe(t);
    return snprintf(out, out_sz,
        "fwknop://%s?name=%s&key=%s&hmac=%s&totp=%s&range=%s&access=%s"
        "&user=%s&v=1",
        c->spa_server[0] ? c->spa_server : "server",
        c->stanza, k, h, t, c->port_range, c->access, c->username);
}

/* Extract a query parameter value from a URI query string. */
static int
uri_get_param(const char *uri, const char *key, char *out, size_t out_sz)
{
    char needle[64];
    const char *p;
    size_t i = 0;
    snprintf(needle, sizeof(needle), "%s=", key);
    /* search must follow a '?' or '&' */
    p = strchr(uri, '?');
    if(p == NULL) p = uri;
    p = strstr(p, needle);
    if(p == NULL)
    {
        /* also try with leading & */
        snprintf(needle, sizeof(needle), "&%s=", key);
        p = strstr(uri, needle);
        if(p == NULL) return 0;
        p += 1; /* skip & */
    }
    p += strlen(key) + 1; /* skip "key=" */
    while(*p && *p != '&' && *p != '#' && i + 1 < out_sz)
        out[i++] = *p++;
    out[i] = '\0';
    return i > 0;
}

int
credential_from_uri(const char *uri, fwknop_credential_t *c)
{
    const char *host_end;
    size_t host_len;
    if(uri == NULL || c == NULL)
        return -1;
    memset(c, 0, sizeof(*c));
    if(strncmp(uri, "fwknop://", 9) != 0)
        return -1;
    host_end = strchr(uri + 9, '?');
    host_len = host_end ? (size_t)(host_end - (uri + 9)) : strlen(uri + 9);
    if(host_len >= sizeof(c->spa_server))
        host_len = sizeof(c->spa_server) - 1;
    memcpy(c->spa_server, uri + 9, host_len);
    c->spa_server[host_len] = '\0';

    uri_get_param(uri, "name",  c->stanza, sizeof(c->stanza));
    uri_get_param(uri, "access", c->access, sizeof(c->access));
    uri_get_param(uri, "range", c->port_range, sizeof(c->port_range));
    uri_get_param(uri, "user",  c->username, sizeof(c->username));
    if(uri_get_param(uri, "key",  c->key_base64, sizeof(c->key_base64)))
        b64_from_urlsafe(c->key_base64);
    if(uri_get_param(uri, "hmac", c->hmac_key_base64, sizeof(c->hmac_key_base64)))
        b64_from_urlsafe(c->hmac_key_base64);
    if(uri_get_param(uri, "totp", c->totp_seed_base64, sizeof(c->totp_seed_base64)))
        b64_from_urlsafe(c->totp_seed_base64);

    if(c->key_base64[0] == '\0' || c->hmac_key_base64[0] == '\0')
        return -2;
    return 0;
}

/***EOF***/
