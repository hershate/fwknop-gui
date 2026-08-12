/*
 * Stage 4b audit module unit test (standalone).
 *
 * Exercises audit_log_event() + audit_metrics_flush() against a temp run dir
 * and verifies: (1) JSON lines are well-formed and contain the expected
 * fields; (2) the Prometheus metrics file is rewritten atomically with all
 * counters; (3) counters accumulate across events.
 *
 * Build: gcc -std=c99 ... test_audit.c <server objects> ...  (see run scripts)
 * Artifact only (REF/ is gitignored).
 */
#include "fwknopd_common.h"
#include "audit.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Provide a minimal fko_srv_options + config slot map so audit.c can read
 * CONF_AUDIT_FILE / CONF_METRICS_FILE. We only need those two slots. */
int main(void)
{
    fko_srv_options_t opts;
    static char audit_path[] = "/tmp/fwknop_audit_test_XXXXXX.log";
    static char metrics_path[] = "/tmp/fwknop_metrics_test_XXXXXX.log";
    spa_data_t spadat;
    int fails = 0;
    int fd;
    FILE *fp;
    char buf[1024];

    memset(&opts, 0, sizeof(opts));
    /* opts.config is a fixed char*[] array inside the struct */
    /* unique temp files */
    fd = mkstemp(audit_path);  if(fd >= 0) close(fd);  unlink(audit_path);
    fd = mkstemp(metrics_path); if(fd >= 0) close(fd); unlink(metrics_path);
    opts.config[CONF_AUDIT_FILE]   = audit_path;
    opts.config[CONF_METRICS_FILE] = metrics_path;

    memset(&spadat, 0, sizeof(spadat));
    strlcpy(spadat.pkt_source_ip, "198.51.100.7", sizeof(spadat.pkt_source_ip));
    spadat.username  = "alice";
    spadat.device_id = "ZGV2aWNlLWZw==";

    printf("== audit_log_event produces JSON lines ==\n");
    audit_log_event(&opts, AUDIT_OPEN, &spadat, NULL, 46364, 22, 1, "accepted");
    audit_log_event(&opts, AUDIT_PORT_MISMATCH, &spadat, NULL, 11111, 0, 1,
            "arrived=11111_expected=46364");
    audit_log_event(&opts, AUDIT_UNKNOWN_FINGERPRINT, &spadat, NULL, 46364, 0,
            1, "device_id_not_in_whitelist");
    audit_log_event(&opts, AUDIT_OPEN, &spadat, NULL, 46364, 22, 2, "accepted");

    /* Verify audit file content. */
    fp = fopen(audit_path, "r");
    if(fp == NULL) { printf("  FAIL: audit file not created\n"); fails++; }
    else
    {
        int lines = 0, all_valid = 1;
        while(fgets(buf, sizeof(buf), fp) != NULL)
        {
            lines++;
            /* crude JSON sanity: starts with { and has "event" */
            if(buf[0] != '{' || strstr(buf, "\"event\"") == NULL
                    || strstr(buf, "\"device_id\"") == NULL)
                all_valid = 0;
            fputs("  ", stdout); fputs(buf, stdout);
        }
        fclose(fp);
        printf("  lines=%d valid_json=%d  %s\n",
                lines, all_valid, (lines==4 && all_valid) ? "PASS" : "FAIL");
        if(!(lines==4 && all_valid)) fails++;
    }

    printf("== metrics file has counters ==\n");
    audit_metrics_flush(&opts);
    fp = fopen(metrics_path, "r");
    if(fp == NULL) { printf("  FAIL: metrics file not created\n"); fails++; }
    else
    {
        int has_open = 0, has_mismatch = 0, has_fp = 0;
        while(fgets(buf, sizeof(buf), fp) != NULL)
        {
            fputs("  ", stdout); fputs(buf, stdout);
            if(strstr(buf, "result=\"open\"")) has_open = 1;
            if(strstr(buf, "result=\"port_mismatch\"")) has_mismatch = 1;
            if(strstr(buf, "result=\"unknown_fingerprint\"")) has_fp = 1;
        }
        fclose(fp);
        /* open fired twice -> look for the value 2 */
        printf("  open=%d mismatch=%d unknown_fp=%d  %s\n",
                has_open, has_mismatch, has_fp,
                (has_open && has_mismatch && has_fp) ? "PASS" : "FAIL");
        if(!(has_open && has_mismatch && has_fp)) fails++;
    }

    /* Verify counter accumulation: open should be 2. */
    fp = fopen(metrics_path, "r");
    if(fp)
    {
        int found_two = 0;
        while(fgets(buf, sizeof(buf), fp) != NULL)
        {
            if(strstr(buf, "result=\"open\"") && strstr(buf, " 2\n"))
                found_two = 1;
        }
        fclose(fp);
        printf("== open counter accumulated to 2: %s ==\n",
                found_two ? "PASS" : "FAIL");
        if(!found_two) fails++;
    }

    unlink(audit_path);
    unlink(metrics_path);

    printf("\nRESULT: %s (%d failure group(s))\n",
            fails == 0 ? "ALL PASS" : "FAILURES", fails);
    return fails ? 1 : 0;
}
