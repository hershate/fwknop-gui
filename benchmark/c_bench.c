/* c_bench.c — libfko 性能基准（SPA 编解码全路径 + 基础算子）
 *
 * 用法: ./c_bench [iter_full] [iter_micro]
 * 输出: JSON 一行（便于脚本聚合）+ 人类可读明细。
 *
 * 原则：
 *  - 全程确定性（固定随机值/用户名/时间戳语义输入），跑多轮结果可直接对比；
 *  - 只测 libfko 公开路径，密钥为测试向量专用，不代表任何真实凭证；
 *  - 不改计时器内部状态，单线程，CLOCK_MONOTONIC。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "fko.h"
#include "sha2.h"
#include "hmac.h"
#include "cipher_funcs.h"

#define BENCH_KEY     "0123456789abcdef0123456789abcdef"   /* 测试向量（32B） */
#define BENCH_HMAC_KEY "0123456789abcdef0123456789abcdef"  /* 测试向量（32B） */

static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

typedef struct { double ns; int iters; const char *name; } result_t;

static result_t timeit(const char *name, int iters, double (*fn)(int))
{
    /* 预热 10 次（页缓存/分支预测稳定），不计入 */
    for (int i = 0; i < 10; i++) fn(i);
    double t0 = now_ns();
    for (int i = 0; i < iters; i++) fn(i);
    double t1 = now_ns();
    result_t r = { (t1 - t0) / iters, iters, name };
    return r;
}

/* ---------- 客户端全路径：构造 + 编码 + 加密 + HMAC，产出最终 SPA 包 ---------- */
static char g_packet[4096];

static double bench_client(int i)
{
    fko_ctx_t ctx = NULL;
    char *spd = NULL;
    (void)i;
    if (fko_new(&ctx) != FKO_SUCCESS) exit(2);
    fko_set_rand_value(ctx, "2468101214161820");         /* 确定性 */
    fko_set_username(ctx, "benchuser");
    fko_set_spa_message(ctx, "127.0.0.1,tcp/22");
    fko_set_spa_client_timeout(ctx, 30);
    fko_set_spa_hmac_type(ctx, FKO_HMAC_SHA256);
    if (fko_spa_data_final(ctx, BENCH_KEY, strlen(BENCH_KEY),
                BENCH_HMAC_KEY, strlen(BENCH_HMAC_KEY)) != FKO_SUCCESS) {
        fprintf(stderr, "encrypt 失败\n");
        exit(3);
    }
    if (fko_get_spa_data(ctx, &spd) != FKO_SUCCESS) exit(4);
    strncpy(g_packet, spd, sizeof(g_packet) - 1);
    fko_destroy(ctx);
    return 0;
}

/* ---------- 服务端全路径：HMAC 校验 + 解密 + 解码 + 摘要比对 ---------- */
static double bench_server(int i)
{
    fko_ctx_t ctx = NULL;
    (void)i;
    {
        int rc = fko_new_with_data(&ctx, g_packet, BENCH_KEY, strlen(BENCH_KEY),
                FKO_ENC_MODE_CBC, BENCH_HMAC_KEY, strlen(BENCH_HMAC_KEY),
                FKO_HMAC_SHA256);
        if (rc != FKO_SUCCESS) { fprintf(stderr, "new_with_data 失败(%d): %s\n", rc, fko_errstr(rc)); exit(5); }
    }
    if (fko_decrypt_spa_data(ctx, BENCH_KEY, strlen(BENCH_KEY)) != FKO_SUCCESS) exit(6);
    fko_destroy(ctx);
    return 0;
}

/* ---------- 基础算子：base64 往返（256B 载荷，接近 SPA 真实体量） ---------- */
static unsigned char g_src[256];
static char g_b64[512];
static unsigned char g_out[512];

static double bench_b64_enc(int i)
{
    (void)i;
    fko_base64_encode(g_src, g_b64, sizeof(g_src));
    return 0;
}

static double bench_b64_dec(int i)
{
    (void)i;
    fko_base64_decode(g_b64, g_out);
    return 0;
}

/* ---------- SHA-256 / HMAC-SHA256（SPA 摘要与认证主体） ---------- */
static double bench_sha256(int i)
{
    (void)i;
    sha256(g_out, g_src, sizeof(g_src));
    return 0;
}

static double bench_hmac(int i)
{
    (void)i;
    hmac_sha256((const char *)g_src, sizeof(g_src), g_out,
                BENCH_HMAC_KEY, (int)strlen(BENCH_HMAC_KEY));
    return 0;
}

/* ---------- AES-128 CBC 加解密（Rijndael，SPA 密文体） ---------- */
static double bench_aes_enc(int i)
{
    (void)i;
    unsigned char out[512];   /* rij_encrypt 输出含 "Salted__" 前缀 + PKCS#7 填充 */
    size_t out_len;
    out_len = rij_encrypt(g_src, sizeof(g_src), BENCH_KEY,
                          (int)strlen(BENCH_KEY), out, FKO_ENC_MODE_CBC);
    if (out_len == 0) exit(20);
    return 0;
}

int main(int argc, char **argv)
{
    int iter_full  = argc > 1 ? atoi(argv[1]) : 2000;
    int iter_micro = argc > 2 ? atoi(argv[2]) : 200000;

    for (unsigned k = 0; k < sizeof(g_src); k++) g_src[k] = (unsigned char)(k * 7 + 3);
    memset(g_b64, 0, sizeof(g_b64));
    memset(g_out, 0, sizeof(g_out));

    /* 先产出一个确定性 SPA 包供服务端基准使用 */
    bench_client(0);

    /* 正确性自检（紧跟产包执行，避免时间流逝带来的状态漂移）：
       server 端解出的 message 必须与设定一致 */
    {
        fko_ctx_t ctx = NULL;
        char *msg = NULL;
        if (fko_new_with_data(&ctx, g_packet, BENCH_KEY, strlen(BENCH_KEY),
                    FKO_ENC_MODE_CBC, BENCH_HMAC_KEY, strlen(BENCH_HMAC_KEY),
                    FKO_HMAC_SHA256) != FKO_SUCCESS) return 10;
        if (fko_decrypt_spa_data(ctx, BENCH_KEY, strlen(BENCH_KEY)) != FKO_SUCCESS) return 11;
        if (fko_get_spa_message(ctx, &msg) != FKO_SUCCESS) return 12;
        if (strcmp(msg, "127.0.0.1,tcp/22") != 0) return 13;
        fko_destroy(ctx);
    }

    result_t R[7]; int ri = 0;
    R[ri++] = timeit("client_full_packet", iter_full,  bench_client);
    R[ri++] = timeit("server_verify_full", iter_full,  bench_server);
    R[ri++] = timeit("b64_encode_256B",    iter_micro, bench_b64_enc);
    R[ri++] = timeit("b64_decode_256B",    iter_micro, bench_b64_dec);
    R[ri++] = timeit("sha256_256B",        iter_micro, bench_sha256);
    R[ri++] = timeit("hmac_sha256_256B",   iter_micro, bench_hmac);
    R[ri++] = timeit("aes_cbc_enc_256B",   iter_micro, bench_aes_enc);
    int n = (int)(sizeof(R) / sizeof(R[0]));

    printf("{\n");
    for (int k = 0; k < n; k++) {
        double ops = 1e9 / R[k].ns;
        printf("  \"%s\": {\"ns_per_op\": %.1f, \"ops_per_sec\": %.0f, \"iters\": %d}%s\n",
               R[k].name, R[k].ns, ops, R[k].iters, k == n - 1 ? "" : ",");
    }
    printf("}\n");

    fprintf(stderr, "%-24s %12s %14s\n", "benchmark", "ns/op", "ops/sec");
    for (int k = 0; k < n; k++)
        fprintf(stderr, "%-24s %12.1f %14.0f\n", R[k].name, R[k].ns, 1e9 / R[k].ns);

    return 0;
}
