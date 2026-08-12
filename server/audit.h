/**
 * \file server/audit.h
 *
 * \brief Stage 4 structured JSON audit + Prometheus metrics (audit.c).
 */
/*  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
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
 ******************************************************************************
*/
#ifndef AUDIT_H
#define AUDIT_H

#include "fwknopd_common.h"

/* Audit event types. Each maps to a JSON "event" value and a Prometheus
 * counter label value. */
typedef enum {
    AUDIT_OPEN = 0,             /* SPA accepted, firewall opened */
    AUDIT_CLOSE,                /* firewall rule expired/closed */
    AUDIT_REJECT,               /* SPA rejected (generic policy) */
    AUDIT_REPLAY,               /* replay digest hit */
    AUDIT_UNKNOWN_FINGERPRINT,  /* device_id not in whitelist / missing */
    AUDIT_PORT_MISMATCH,        /* REQUIRE_TOTP_PORT_MATCH failed */
    AUDIT_AGED,                 /* SPA packet too old */
    AUDIT_TOFU_BIND,            /* TOFU bound a new device_id */
    AUDIT_EVENT_COUNT
} audit_event_t;

/**
 * \brief Append one structured audit event as a JSON line.
 *
 * Writes a single-line JSON object to the configured AUDIT_FILE (and forwards
 * to syslog at LOG_INFO). Any of the string pointers may be NULL. spa_port is
 * the destination port the packet arrived on; target_port is the service port
 * being opened (0 if N/A). reason is a short human-readable detail string.
 *
 * Counters for Prometheus are also incremented here; call audit_metrics_flush()
 * periodically (or on each event) to (re)write the metrics file.
 */
void audit_log_event(const fko_srv_options_t *opts, audit_event_t ev,
        const spa_data_t *spadat, const char *src_ip,
        unsigned int spa_port, unsigned int target_port,
        int stanza_num, const char *reason);

/**
 * \brief (Re)write the Prometheus metrics file from the in-memory counters.
 *
 * Produces a text exposition at METRICS_FILE with counters such as
 * fwknop_spa_packets_total{result="open"} N. Safe to call on every event or
 * on a timer; it rewrites the whole file atomically (temp + rename).
 */
void audit_metrics_flush(const fko_srv_options_t *opts);

#endif /* AUDIT_H */

/***EOF***/
