/**
 * \file lib/base64.c
 *
 * \brief Implementation of the Base64 encode/decode algorithim.
 */

/* This code was derived from the base64.c part of FFmpeg written
 * by Ryan Martell. (rdm4@martellventures.com).
 *
 * Copyright (C) Ryan Martell. (rdm4@martellventures.com)
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
 *
 *  This library is free software; you can redistribute it and/or
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
 *****************************************************************************
*/
#include "base64.h"
#include "fko_common.h"


#ifdef HAVE_C_UNIT_TESTS /* LCOV_EXCL_START */
#include "cunit_common.h"
DECLARE_TEST_SUITE(base64_test, "Utility functions test suite");
#endif /* LCOV_EXCL_STOP */

int
b64_decode(const char *in, unsigned char *out)
{
    unsigned char *dst = out;
#if ! AFL_FUZZING
    /* R1 性能重写：与原逐字符实现语义逐字节一致——
     *   - 遇 NUL 或 '=' 终止；非法字符返回 -1（调用方不使用部分输出）；
     *   - 输出追加 NUL，返回输出字节数。
     * 完整 256 项值表：合法字符 -> 6bit 值，其余 0xff（生成脚本核对过
     * 与原 map2 布尔表语义一致）。 */
    static const unsigned char val256[256] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    int have = 0;                 /* 已积累的 bit 数（0/2/4/6/8...） */
    unsigned int acc = 0;

    for (;;) {
        unsigned char v;
        unsigned char c = (unsigned char)*in;

        if (c == '\0' || c == '=')
            break;

        v = val256[c];
        if (v == 0xff)
            return(-1);

        acc = (acc << 6) | v;
        have += 6;
        in++;

        if (have >= 8) {
            have -= 8;
            *dst++ = (unsigned char)(acc >> have);
        }
    }
    *dst = '\0';
    return (int)(dst - out);
#else
    /* short circuit base64 decoding in AFL fuzzing mode - just copy
     * data as-is.
    */
    for (; *in; in++)
        *dst++ = *in;
    *dst = '\0';
    return(dst - out);
#endif
}

/*****************************************************************************
 * b64_encode: R1 性能重写（3 字节 -> 4 字符位打包），
 * 输出与原 VLC 风格逐字符实现逐字节一致（含 '=' 填充与 NUL 结尾）。
 *****************************************************************************
*/
int
b64_encode(unsigned char *in, char *out, int in_len)
{
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *dst = out;

    if (in_len > 0) {
        int n3 = in_len / 3;      /* 完整 3 字节组 */
        int rem = in_len - n3 * 3;

        while (n3--) {
            unsigned int w = ((unsigned int)in[0] << 16)
                           | ((unsigned int)in[1] << 8)
                           |  (unsigned int)in[2];
            in += 3;
            *dst++ = b64[(w >> 18) & 0x3f];
            *dst++ = b64[(w >> 12) & 0x3f];
            *dst++ = b64[(w >>  6) & 0x3f];
            *dst++ = b64[ w        & 0x3f];
        }

        if (rem == 1) {
            unsigned int w = (unsigned int)in[0] << 16;
            *dst++ = b64[(w >> 18) & 0x3f];
            *dst++ = b64[(w >> 12) & 0x3f];
            *dst++ = '=';
            *dst++ = '=';
        } else if (rem == 2) {
            unsigned int w = ((unsigned int)in[0] << 16)
                           | ((unsigned int)in[1] << 8);
            *dst++ = b64[(w >> 18) & 0x3f];
            *dst++ = b64[(w >> 12) & 0x3f];
            *dst++ = b64[(w >>  6) & 0x3f];
            *dst++ = '=';
        }
    }

    *dst = '\0';

    return(dst - out);
}

/* Strip trailing equals ("=") charcters from a base64-encoded
 * message digest.
*/
void
strip_b64_eq(char *data)
{
    char *ndx;

    if((ndx = strchr(data, '=')) != NULL)
        *ndx = '\0';
}

#ifdef HAVE_C_UNIT_TESTS /* LCOV_EXCL_START */
DECLARE_UTEST(test_base64_encode, "test base64 encoding functions")
{
    char test_str[32] = {0};
    char test_out[32] = {0};
    char expected_out1[32] = {0};
    char expected_out2[32] = {0};
    char expected_out3[32] = {0};
    char expected_out4[32] = {0};
    char expected_out5[32] = {0};
    char expected_out6[32] = {0};
    char expected_out7[32] = {0};

    strcpy(expected_out1, "");
    strcpy(expected_out2, "Zg==");
    strcpy(expected_out3, "Zm8=");
    strcpy(expected_out4, "Zm9v");
    strcpy(expected_out5, "Zm9vYg==");
    strcpy(expected_out6, "Zm9vYmE=");
    strcpy(expected_out7, "Zm9vYmFy");

    strcpy(test_str, "");
    b64_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out1) == 0);

    strcpy(test_str, "f");
    b64_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out2) == 0);

    strcpy(test_str, "fo");
    b64_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out3) == 0);

    strcpy(test_str, "foo");
    b64_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out4) == 0);

    strcpy(test_str, "foob");
    b64_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out5) == 0);

    strcpy(test_str, "fooba");
    b64_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out6) == 0);

    strcpy(test_str, "foobar");
    b64_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out7) == 0);

}

DECLARE_UTEST(test_base64_decode, "test base64 decoding functions")
{
    char test_str[32] = {0};
    char test_out[32] = {0};
    char expected_out1[32] = {0};
    char expected_out2[32] = {0};
    char expected_out3[32] = {0};
    char expected_out4[32] = {0};
    char expected_out5[32] = {0};
    char expected_out6[32] = {0};
    char expected_out7[32] = {0};

    strcpy(expected_out1, "");
    strcpy(expected_out2, "f");
    strcpy(expected_out3, "fo");
    strcpy(expected_out4, "foo");
    strcpy(expected_out5, "foob");
    strcpy(expected_out6, "fooba");
    strcpy(expected_out7, "foobar");

    strcpy(test_str, "");
    b64_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out1) == 0);

    strcpy(test_str, "Zg==");
    b64_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out2) == 0);

    strcpy(test_str, "Zm8=");
    b64_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out3) == 0);

    strcpy(test_str, "Zm9v");
    b64_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out4) == 0);

    strcpy(test_str, "Zm9vYg==");
    b64_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out5) == 0);

    strcpy(test_str, "Zm9vYmE=");
    b64_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out6) == 0);

    strcpy(test_str, "Zm9vYmFy");
    b64_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out7) == 0);
}

int register_base64_test(void)
{
    ts_init(&TEST_SUITE(base64_test), TEST_SUITE_DESCR(base64_test), NULL, NULL);
    ts_add_utest(&TEST_SUITE(base64_test), UTEST_FCT(test_base64_encode), UTEST_DESCR(test_base64_encode));
    ts_add_utest(&TEST_SUITE(base64_test), UTEST_FCT(test_base64_decode), UTEST_DESCR(test_base64_decode));

    return register_ts(&TEST_SUITE(base64_test));
}
#endif /* LCOV_EXCL_STOP */
/***EOF***/
