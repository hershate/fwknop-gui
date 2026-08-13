/**
 * \file server/audit.c
 *
 * \brief Stage 4 structured JSON audit + Prometheus metrics.
 *
 * Each audit event is written as one JSON line to AUDIT_FILE and forwarded to
 * syslog at LOG_INFO. Prometheus-format counters are kept in memory and the
 * METRICS_FILE is rewritten (atomically) on audit_metrics_flush(). This keeps
 * a Web panel / node_exporter textfile collector decoupled from the C daemon
 * (see REF/plan/Port Knocking.md Sec.7.4/Sec.7.6).
 */
/*  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors.
 *
 *  License (GNU General Public License) version 2 or (at your option) any
 *  later version. See COPYING.
 ******************************************************************************
*/
#include "fwknopd_common.h"
#include "audit.h"
#include "log_msg.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

/* Counter storage. Indexed by audit_event_t. */
static unsigned long audit_counters[AUDIT_EVENT_COUNT] = {0};

/* JSON event name per audit_event_t. Order matches the enum. */
static const char *const audit_event_names[AUDIT_EVENT_COUNT] = {
    "open", "close", "reject", "replay",
    "unknown_fingerprint", "port_mismatch", "aged", "tofu_bind"
};

/* Prometheus result label per event (same order). */
static const char *const audit_metric_labels[AUDIT_EVENT_COUNT] = {
    "open", "close", "reject", "replay",
    "unknown_fingerprint", "port_mismatch", "aged", "tofu_bind"
};

/* Escape a string into out (JSON-safe: quotes and backslashes). in may be
 * NULL. out is NUL-terminated. Returns the number of bytes written. */
static size_t
json_escape(const char *in, char *out, size_t out_sz)
{
    size_t i = 0;
    if(in == NULL)
    {
        if(out_sz > 0) out[0] = '\0';
        return 0;
    }
    while(*in && i + 2 < out_sz)
    {
        if(*in == '"' || *in == '\\')
        {
            if(i + 2 >= out_sz) break;
            out[i++] = '\\';
            out[i++] = *in++;
        }
        else if((unsigned char)*in < 0x20)
        {
            /* control char -> skip (device_id is validated printable anyway) */
            in++;
        }
        else
            out[i++] = *in++;
    }
    if(out_sz > 0) out[i] = '\0';
    return i;
}

void
audit_log_event(const fko_srv_options_t *opts, audit_event_t ev,
        const spa_data_t *spadat, const char *src_ip,
        unsigned int spa_port, unsigned int target_port,
        int stanza_num, const char *reason)
{
    char line[512] = {0};
    char user[128] = {0};
    char dev[192] = {0};
    char ipbuf[MAX_IPV4_STR_LEN] = {0};
    char reason_buf[160] = {0};
    const char *sip = NULL;
    int n, fd;

    if(ev < 0 || ev >= AUDIT_EVENT_COUNT)
        return;

    /* Only act if audit is enabled (or always bump counters for metrics). */
    audit_counters[ev]++;

    sip = src_ip;
    if(sip == NULL && spadat != NULL)
        sip = spadat->pkt_source_ip;
    if(sip != NULL)
        strlcpy(ipbuf, sip, sizeof(ipbuf));

    if(spadat != NULL)
    {
        json_escape(spadat->username, user, sizeof(user));
        json_escape(spadat->device_id, dev, sizeof(dev));
    }
    json_escape(reason, reason_buf, sizeof(reason_buf));

    n = snprintf(line, sizeof(line),
        "{\"time\":%ld,\"event\":\"%s\",\"user\":\"%s\",\"device_id\":\"%s\","
        "\"src_ip\":\"%s\",\"spa_port\":%u,\"target_port\":%u,"
        "\"stanza\":%d,\"reason\":\"%s\"}\n",
        (long)time(NULL),
        audit_event_names[ev],
        user, dev, ipbuf,
        spa_port, target_port, stanza_num, reason_buf);

    if(n < 0)
        return;

    /* Forward to syslog regardless (so audit is visible even without file). */
    log_msg(LOG_INFO, "audit: %.*s",
        (n > 0 && line[n-1] == '\n') ? n - 1 : n, line);

    /* Append JSON line to the audit file. */
    if(opts != NULL && opts->config[CONF_AUDIT_FILE] != NULL
        && opts->config[CONF_AUDIT_FILE][0] != '\0')
    {
        fd = open(opts->config[CONF_AUDIT_FILE],
                O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR);
        if(fd >= 0)
        {
            if(write(fd, line, strlen(line)) < 0)
            { /* best effort */ }
            close(fd);
        }
    }

    /* Rewrite the metrics file so a scraper always sees fresh counters. */
    audit_metrics_flush(opts);
    return;
}

void
audit_metrics_flush(const fko_srv_options_t *opts)
{
    char tmp[MAX_PATH_LEN] = {0};
    char final[MAX_PATH_LEN] = {0};
    FILE *fp = NULL;
    int i;

    if(opts == NULL || opts->config[CONF_METRICS_FILE] == NULL
        || opts->config[CONF_METRICS_FILE][0] == '\0')
        return;

    snprintf(tmp, sizeof(tmp), "%s.tmp", opts->config[CONF_METRICS_FILE]);
    strlcpy(final, opts->config[CONF_METRICS_FILE], sizeof(final));

    fp = fopen(tmp, "w");
    if(fp == NULL)
    {
        log_msg(LOG_WARNING, "audit: could not open metrics temp file %s: %s",
            tmp, strerror(errno));
        return;
    }

    fprintf(fp, "# HELP fwknop_spa_packets_total SPA packets by result\n");
    fprintf(fp, "# TYPE fwknop_spa_packets_total counter\n");
    for(i = 0; i < AUDIT_EVENT_COUNT; i++)
    {
        fprintf(fp, "fwknop_spa_packets_total{result=\"%s\"} %lu\n",
            audit_metric_labels[i], audit_counters[i]);
    }
    fclose(fp);

    /* Atomic publish. */
    if(rename(tmp, final) != 0)
        log_msg(LOG_WARNING, "audit: rename(%s,%s) failed: %s",
            tmp, final, strerror(errno));
    return;
}

/***EOF***/
