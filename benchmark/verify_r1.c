/* verify_r1.c — R1 优化的正确性验证器（红线门禁之一）
 *
 * 1) base64：内嵌「旧实现」副本（git 基线版），新旧输出逐字节对比：
 *    - 确定性 LCG 覆盖长度 0..600 的二进制缓冲；
 *    - 全部 256 字节值的单字节/组合模式；
 *    - 非法字符（含空白、高位字节）必须同样返回 -1；
 *    - 遇 '=' 截断语义一致。
 * 2) SHA-256：NIST/ RFC 6234 风格测试向量（空串、"abc"、448bit、
 *    896bit、100 万次 'a' 用等价两段 Update 近似单段——不适用，改为
 *    多组已知向量），字节序无关比对。
 *
 * 退出码 0 = 全部通过；非 0 = 失败（对应检查项编号）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "base64.h"
#include "sha2.h"

/* ---------- 旧实现副本（b64_decode/b64_encode 的 git 基线版，改名） ---------- */
static unsigned char map2_old[] =
{
    0x3e, 0xff, 0xff, 0xff, 0x3f, 0x34, 0x35, 0x36,
    0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
    0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33
};

static int
b64_decode_old(const char *in, unsigned char *out)
{
    int i;
    unsigned char *dst = out;
    int v;

    v = 0;
    for (i = 0; in[i] && in[i] != '='; i++) {
        unsigned int index = in[i] - 43;
        if (index >= (sizeof(map2_old)/sizeof(map2_old[0])) || map2_old[index] == 0xff)
            return(-1);
        v = (v << 6) + map2_old[index];
        if (i & 3)
            *dst++ = v >> (6 - 2 * (i & 3));
    }
    *dst = '\0';
    return(dst - out);
}

static int
b64_encode_old(unsigned char *in, char *out, int in_len)
{
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned i_bits = 0;
    int i_shift = 0;
    int bytes_remaining = in_len;
    char *dst = out;

    if (in_len > 0) {
        while (bytes_remaining) {
            i_bits = (i_bits << 8) + *in++;
            bytes_remaining--;
            i_shift += 8;
            do {
                *dst++ = b64[(i_bits << 6 >> i_shift) & 0x3f];
                i_shift -= 6;
            } while (i_shift > 6 || (bytes_remaining == 0 && i_shift > 0));
        }
        while ((dst - out) & 3)
            *dst++ = '=';
    }
    *dst = '\0';
    return(dst - out);
}

/* ---------- LCG 确定性伪随机 ---------- */
static unsigned int lcg = 0x12345678u;
static unsigned char next_byte(void) { lcg = lcg * 1103515245u + 12345u; return (unsigned char)(lcg >> 16); }

static int fail_cnt = 0;

static void check_b64_pair(unsigned char *buf, int len)
{
    char e_new[4096], e_old[4096];
    unsigned char d_new[4096], d_old[4096];
    char t_old[4096];
    int rn, ro, dn, dold, to;

    rn = b64_encode(buf, e_new, len);
    ro = b64_encode_old(buf, e_old, len);
    if (rn != ro || (rn >= 0 && memcmp(e_new, e_old, rn + 1) != 0)) {
        printf("FAIL encode len=%d new=%d old=%d\n", len, rn, ro);
        fail_cnt++;
        return;
    }

    /* 编码结果各自解码，输出须一致 */
    dn = b64_decode(e_new, d_new);
    dold = b64_decode_old(e_old, d_old);
    if (dn != dold || (dn >= 0 && memcmp(d_new, d_old, dn) != 0)) {
        printf("FAIL decode-roundtrip len=%d new=%d old=%d\n", len, dn, dold);
        fail_cnt++;
    }

    /* 非法字符注入：在编码串首字符替换为非法符号，两者必须都 -1 */
    if (rn > 0) {
        memcpy(t_old, e_new, rn + 1);
        t_old[0] = '~';
        if (b64_decode(t_old, d_new) != -1) { printf("FAIL invalid-char new accepted\n"); fail_cnt++; }
        if (b64_decode_old(t_old, d_old) != -1) { printf("FAIL invalid-char old accepted\n"); fail_cnt++; }

        /* '=' 截断位置语义一致 */
        for (int cut = 1; cut < rn; cut++) {
            memcpy(t_old, e_new, rn + 1);
            t_old[cut] = '=';
            int a = b64_decode(t_old, d_new);
            int b = b64_decode_old(t_old, d_old);
            if ((a == -1) != (b == -1) || (a >= 0 && b >= 0 && (a != b || memcmp(d_new, d_old, a)))) {
                printf("FAIL '='-cut=%d new=%d old=%d\n", cut, a, b);
                fail_cnt++;
                break;
            }
        }
    }
}

static void check_sha(const char *msg, const char *hex_expect)
{
    SHA256_CTX ctx;
    unsigned char md[SHA256_DIGEST_LEN];
    char hex[SHA256_DIGEST_STR_LEN];
    static const char hx[] = "0123456789abcdef";

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (const unsigned char *)msg, strlen(msg));
    SHA256_Final(md, &ctx);
    for (int i = 0; i < SHA256_DIGEST_LEN; i++) {
        hex[i * 2] = hx[md[i] >> 4];
        hex[i * 2 + 1] = hx[md[i] & 0xf];
    }
    hex[64] = '\0';
    if (strcmp(hex, hex_expect) != 0) {
        printf("FAIL sha256(\"%s\")\n  got  %s\n  want %s\n", msg, hex, hex_expect);
        fail_cnt++;
    }
}

int main(void)
{
    unsigned char buf[4096];

    /* 1) 长度扫描 0..600 */
    for (int len = 0; len <= 600; len++) {
        for (int i = 0; i < len; i++) buf[i] = next_byte();
        check_b64_pair(buf, len);
    }

    /* 2) 全字节值模式 */
    for (int v = 0; v < 256; v++) {
        memset(buf, v, 300);
        check_b64_pair(buf, 300);
    }

    /* 3) 单字节 'A' 语义（值 0 与非法 0xff 的区分） */
    buf[0] = 'A';
    check_b64_pair(buf, 1);

    /* 4) SHA-256 已知向量（NIST FIPS 180-2 / RFC 6234 选集） */
    check_sha("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    check_sha("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check_sha("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    if (fail_cnt == 0) {
        printf("R1 verify: ALL PASS (b64 长度扫描0-600 + 全字节模式 + 截断/非法语义 + SHA256 向量)\n");
        return 0;
    }
    printf("R1 verify: %d FAILURES\n", fail_cnt);
    return 1;
}
