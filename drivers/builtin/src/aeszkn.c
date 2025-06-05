/*
 *  AES-ZKN support functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * https://github.com/riscv/riscv-crypto/releases/download/v1.0.1-scalar/riscv-crypto-spec-scalar-v1.0.1.pdf
 */

#include "common.h"
#include <string.h>

#if defined(MBEDTLS_AESZKN_C)
#include "aeszkn.h"

#if defined(MBEDTLS_AESZKN_HAVE_CODE)
#if defined(__linux__) && !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)
#include <sys/hwprobe.h>
#define RISCV_HWPROBE_EXT_ZKND (1 << 11)
#define RISCV_HWPROBE_EXT_ZKNE (1 << 12)

/*
 * AES-ZKN support detection routine
 */
int mbedtls_aeszkn_has_support(void)
{
    struct riscv_hwprobe pair;
    long rc;

    pair.key = RISCV_HWPROBE_KEY_IMA_EXT_0;
    rc = __riscv_hwprobe(&pair, 1, 0, NULL, 0);
    if (rc == 0) {
        if (pair.value & (RISCV_HWPROBE_EXT_ZKND | RISCV_HWPROBE_EXT_ZKNE))
            return 1;
    }

	return 0;
}
#endif /* defined(__linux__) && !defined(MBEDTLS_AES_USE_HARDWARE_ONLY) */

/*
 * Key expansion for encryption, 128-bit case
 */
static void __attribute__((naked)) aes_128_enc_ks(unsigned char *rk,
                             const unsigned char *ck,
                             const unsigned char *rc)
{
    (void) rk;
    (void) ck;
    (void) rc;

#if defined(MBEDTLS_ARCH_IS_RISCV32)
    asm ("mv t1, a2    \n\t" // round constant
         "lw a2, 0(a1)    \n\t" // load cipher key
         "lw a3, 4(a1)    \n\t"
         "lw a4, 8(a1)    \n\t"
         "lw a5, 12(a1)  \n\t"
         "mv a6, a0        \n\t"
         "addi t0, a0, 160    \n\t" // expand for 10 round
         ".aes_128_enc_ks_l0:\n\t"
         "sw a2, 0(a6)        \n\t" // save round key in rk
         "sw a3, 4(a6)    \n\t"
         "sw a4, 8(a6)    \n\t"
         "sw a5, 12(a6)   \n\t"
         "beq t0, a6, aes_128_enc_ks_finish    \n\t"
         "addi a6, a6, 16    \n\t" // next round key
         "lbu t2, 0(t1)    \n\t" // load round constant
         "addi t1, t1, 1    \n\t"
         "xor a2, a2, t2    \n\t"
         "srli t4, a5, 8      \n\t"
         "slli t3, a5, (32-8)    \n\t"
         "or t3, t3, t4    \n\t"
         "aes32esi a2, a2, t3, 0    \n\t"
         "aes32esi a2, a2, t3, 1    \n\t"
         "aes32esi a2, a2, t3, 2    \n\t"
         "aes32esi a2, a2, t3, 3    \n\t"
         "xor a3, a3, a2    \n\t"
         "xor a4, a4, a3    \n\t"
         "xor a5, a5, a4    \n\t"
         "j .aes_128_enc_ks_l0    \n\t"
         "aes_128_enc_ks_finish:    \n\t"
         "ret    \n\t");
#else
    asm ("ld a2, 0(a1)    \n\t" // load cipher key
         "ld a3, 8(a1)    \n\t"
         "sd a2, 0(a0)        \n\t" // save round key in rk
         "sd a3, 8(a0)    \n\t"
         "aes64ks1i t3 , a3, 0    \n\t"
         "aes64ks2 a2, t3 , a2    \n\t"
         "aes64ks2 a3, a2, a3    \n\t"
         "sd a2, 16(a0)        \n\t"
         "sd a3, 24(a0)    \n\t"
         "aes64ks1i t3 , a3, 1    \n\t"
         "aes64ks2 a2, t3 , a2    \n\t"
         "aes64ks2 a3, a2, a3    \n\t"
         "sd a2, 32(a0)        \n\t"
         "sd a3, 40(a0)    \n\t"
         "aes64ks1i t3 , a3, 2    \n\t"
         "aes64ks2 a2, t3 , a2    \n\t"
         "aes64ks2 a3, a2, a3    \n\t"
         "sd a2, 48(a0)        \n\t"
         "sd a3, 56(a0)    \n\t"
         "aes64ks1i t3 , a3, 3    \n\t"
         "aes64ks2 a2, t3 , a2    \n\t"
         "aes64ks2 a3, a2, a3    \n\t"
         "sd a2, 64(a0)        \n\t"
         "sd a3, 72(a0)    \n\t"
         "aes64ks1i t3 , a3, 4    \n\t"
         "aes64ks2 a2, t3 , a2    \n\t"
         "aes64ks2 a3, a2, a3    \n\t"
         "sd a2, 80(a0)        \n\t"
         "sd a3, 88(a0)    \n\t"
         "aes64ks1i t3 , a3, 5    \n\t"
         "aes64ks2 a2, t3 , a2    \n\t"
         "aes64ks2 a3, a2, a3    \n\t"
         "sd a2, 96(a0)        \n\t"
         "sd a3, 104(a0)    \n\t"
         "aes64ks1i t3 , a3, 6    \n\t"
         "aes64ks2 a2, t3 , a2    \n\t"
         "aes64ks2 a3, a2, a3    \n\t"
         "sd a2, 112(a0)        \n\t"
         "sd a3, 120(a0)    \n\t"
         "aes64ks1i t3 , a3, 7    \n\t"
         "aes64ks2 a2, t3 , a2    \n\t"
         "aes64ks2 a3, a2, a3    \n\t"
         "sd a2, 128(a0)        \n\t"
         "sd a3, 136(a0)    \n\t"
         "aes64ks1i t3 , a3, 8    \n\t"
         "aes64ks2 a2, t3 , a2    \n\t"
         "aes64ks2 a3, a2, a3    \n\t"
         "sd a2, 144(a0)        \n\t"
         "sd a3, 152(a0)    \n\t"
         "aes64ks1i t3 , a3, 9    \n\t"
         "aes64ks2 a2, t3 , a2    \n\t"
         "aes64ks2 a3, a2, a3    \n\t"
         "sd a2, 160(a0)        \n\t"
         "sd a3, 168(a0)    \n\t"
         "ret    \n\t");
#endif /* MBEDTLS_ARCH_IS_RISCV32 */
}

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
/*
 * Key expansion for encryption, 192-bit case
 */
static void __attribute__((naked)) aes_192_enc_ks(unsigned char *rk,
                             const unsigned char *ck,
                             const unsigned char *rc)
{
    (void) rk;
    (void) ck;
    (void) rc;

#if defined(MBEDTLS_ARCH_IS_RISCV32)
    asm ("mv t1, a2    \n\t" // round constant
         "lw a2, 0(a1)    \n\t"
         "lw a3, 4(a1)    \n\t"
         "lw a4, 8(a1)    \n\t"
         "lw a5, 12(a1)    \n\t"
         "lw a7, 16(a1)    \n\t"
         "lw t5, 20(a1)    \n\t"
         "mv a6, a0    \n\t"
         "addi t0, a0, 48*4    \n\t" // expand for 12 round
         ".aes_192_enc_ks_l0:    \n\t"
         "sw a2, 0(a6)    \n\t"
         "sw a3, 4(a6)    \n\t"
         "sw a4, 8(a6)    \n\t"
         "sw a5, 12(a6)    \n\t"
         "beq t0, a6, aes_192_enc_ks_finish    \n\t"
         "sw a7, 16(a6)    \n\t"
         "sw t5, 20(a6)    \n\t"
         "addi a6, a6, 24    \n\t" // next round key
         "lbu t4, 0(t1)    \n\t" // load round constant
         "addi t1, t1, 1    \n\t"
         "xor a2, a2, t4    \n\t"
         "srli t4, t5, 8    \n\t"
         "slli t3, t5, (32-8)    \n\t"
         "or t3, t3, t4    \n\t"
         "aes32esi a2, a2, t3, 0    \n\t"
         "aes32esi a2, a2, t3, 1    \n\t"
         "aes32esi a2, a2, t3, 2    \n\t"
         "aes32esi a2, a2, t3, 3    \n\t"
         "xor a3, a3, a2    \n\t"
         "xor a4, a4, a3    \n\t"
         "xor a5, a5, a4    \n\t"
         "xor a7, a7, a5    \n\t"
         "xor t5, t5, a7    \n\t"
         "j .aes_192_enc_ks_l0    \n\t"
         "aes_192_enc_ks_finish:    \n\t"
         "ret    \n\t");
#else
    asm ("ld a2, 0(a1)    \n\t"
         "ld a3, 8(a1)    \n\t"
         "ld a4, 16(a1)    \n\t"
         "sd a2, 0(a0)    \n\t"
         "sd a3, 8(a0)    \n\t"
         "sd a4, 16(a0)    \n\t"
         "aes64ks1i t2, a4, 0    \n\t"
         "aes64ks2  a2,t2, a2    \n\t"
         "aes64ks2  a3, a2, a3    \n\t"
         "aes64ks2  a4, a3, a4    \n\t"
         "sd a2, 24(a0)    \n\t"
         "sd a3, 32(a0)    \n\t"
         "sd a4, 40(a0)    \n\t"
         "aes64ks1i t2, a4, 1    \n\t"
         "aes64ks2  a2,t2, a2    \n\t"
         "aes64ks2  a3, a2, a3    \n\t"
         "aes64ks2  a4, a3, a4    \n\t"
         "sd a2, 48(a0)    \n\t"
         "sd a3, 56(a0)    \n\t"
         "sd a4, 64(a0)    \n\t"
         "aes64ks1i t2, a4, 2    \n\t"
         "aes64ks2  a2,t2, a2    \n\t"
         "aes64ks2  a3, a2, a3    \n\t"
         "aes64ks2  a4, a3, a4    \n\t"
         "sd a2, 72(a0)    \n\t"
         "sd a3, 80(a0)    \n\t"
         "sd a4, 88(a0)    \n\t"
         "aes64ks1i t2, a4, 3    \n\t"
         "aes64ks2  a2,t2, a2    \n\t"
         "aes64ks2  a3, a2, a3    \n\t"
         "aes64ks2  a4, a3, a4    \n\t"
         "sd a2, 96(a0)    \n\t"
         "sd a3, 104(a0)    \n\t"
         "sd a4, 112(a0)    \n\t"
         "aes64ks1i t2, a4, 4    \n\t"
         "aes64ks2  a2,t2, a2    \n\t"
         "aes64ks2  a3, a2, a3    \n\t"
         "aes64ks2  a4, a3, a4    \n\t"
         "sd a2, 120(a0)    \n\t"
         "sd a3, 128(a0)    \n\t"
         "sd a4, 136(a0)    \n\t"
         "aes64ks1i t2, a4, 5    \n\t"
         "aes64ks2  a2,t2, a2    \n\t"
         "aes64ks2  a3, a2, a3    \n\t"
         "aes64ks2  a4, a3, a4    \n\t"
         "sd a2, 144(a0)    \n\t"
         "sd a3, 152(a0)    \n\t"
         "sd a4, 160(a0)    \n\t"
         "aes64ks1i t2, a4, 6    \n\t"
         "aes64ks2  a2,t2, a2    \n\t"
         "aes64ks2  a3, a2, a3    \n\t"
         "aes64ks2  a4, a3, a4    \n\t"
         "sd a2, 168(a0)    \n\t"
         "sd a3, 176(a0)    \n\t"
         "sd a4, 184(a0)    \n\t"
         "aes64ks1i t2, a4, 7    \n\t"
         "aes64ks2  a2,t2, a2    \n\t"
         "aes64ks2  a3, a2, a3    \n\t"
         "sd a2, 192(a0)    \n\t"
         "sd a3, 200(a0)    \n\t"
         "ret    \n\t");
#endif /* MBEDTLS_ARCH_IS_RISCV32 */
}

/*
 * Key expansion for encryption, 256-bit case
 */
static void __attribute__((naked)) aes_256_enc_ks (unsigned char *rk,
                             const unsigned char *ck,
                             const unsigned char *rc)
{
    (void) rk;
    (void) ck;
    (void) rc;

#if defined(MBEDTLS_ARCH_IS_RISCV32)
    asm ("mv t1, a2    \n\t"
         "lw a2, 0(a1)    \n\t"
         "lw a3, 4(a1)    \n\t"
         "lw a4, 8(a1)    \n\t"
         "lw a5, 12(a1)    \n\t"
         "lw a7, 16(a1)    \n\t"
         "lw t5, 20(a1)    \n\t"
         "lw t6, 24(a1)    \n\t"
         "lw t2, 28(a1)    \n\t"
         "mv a6, a0    \n\t"
         "addi t0, a0, 56*4    \n\t" // expand for 14 round
         "sw a2, 0(a6)    \n\t"
         "sw a3, 4(a6)    \n\t"
         "sw a4, 8(a6)    \n\t"
         "sw a5, 12(a6)    \n\t"
         ".aes_256_enc_ks_l0:    \n\t"
         "sw a7, 16(a6)    \n\t"
         "sw t5, 20(a6)    \n\t"
         "sw t6, 24(a6)    \n\t"
         "sw t2, 28(a6)    \n\t"
         "addi a6, a6, 32    \n\t"
         "lbu t4, 0(t1)    \n\t"
         "addi t1, t1, 1    \n\t"
         "xor a2, a2, t4    \n\t"
         "srli t4, t2, 8    \n\t"
         "slli t3, t2, (32-8)    \n\t"
         "or t3, t3, t4    \n\t"
         "aes32esi a2, a2, t3, 0    \n\t"
         "aes32esi a2, a2, t3, 1    \n\t"
         "aes32esi a2, a2, t3, 2    \n\t"
         "aes32esi a2, a2, t3, 3    \n\t"
         "xor a3, a3, a2    \n\t"
         "xor a4, a4, a3    \n\t"
         "xor a5, a5, a4    \n\t"
         "sw a2, 0(a6)    \n\t"
         "sw a3, 4(a6)    \n\t"
         "sw a4, 8(a6)    \n\t"
         "sw a5, 12(a6)    \n\t"
         "beq t0, a6, aes_256_enc_ks_finish    \n\t"
         "aes32esi a7, a7, a5, 0    \n\t"
         "aes32esi a7, a7, a5, 1    \n\t"
         "aes32esi a7, a7, a5, 2    \n\t"
         "aes32esi a7, a7, a5, 3    \n\t"
         "xor t5, t5, a7    \n\t"
         "xor t6, t6, t5    \n\t"
         "xor t2, t2, t6    \n\t"
         "j .aes_256_enc_ks_l0    \n\t"
         "aes_256_enc_ks_finish:    \n\t"
         "ret    \n\t");
#else
    asm ("ld a2, 0(a1)    \n\t"
         "ld a3, 8(a1)    \n\t"
         "ld a4, 16(a1)    \n\t"
         "ld a5, 24(a1)    \n\t"
         "sd a2, 0(a0)    \n\t"
         "sd a3, 8(a0)    \n\t"
         "sd a4, 16(a0)    \n\t"
         "sd a5, 24(a0)    \n\t"
         "aes64ks1i t2, a5, 0    \n\t"
         "aes64ks2  a2,t2, a2    \n\t"
         "aes64ks2  a3, a2, a3    \n\t"
         "aes64ks1i t2, a3, 0xa    \n\t"
         "aes64ks2  a4,t2, a4    \n\t"
         "aes64ks2  a5, a4, a5    \n\t"
         "sd a2, 32(a0)    \n\t"
         "sd a3, 40(a0)    \n\t"
         "sd a4, 48(a0)    \n\t"
         "sd a5, 56(a0)    \n\t"
         "aes64ks1i t2, a5, 1    \n\t"
         "aes64ks2  a2,t2, a2    \n\t"
         "aes64ks2  a3, a2, a3    \n\t"
         "aes64ks1i t2, a3, 0xa    \n\t"
         "aes64ks2  a4,t2, a4    \n\t"
         "aes64ks2  a5, a4, a5    \n\t"
         "sd a2, 64(a0)    \n\t"
         "sd a3, 72(a0)    \n\t"
         "sd a4, 80(a0)    \n\t"
         "sd a5, 88(a0)    \n\t"
         "aes64ks1i t2, a5, 2    \n\t"
         "aes64ks2  a2,t2, a2    \n\t"
         "aes64ks2  a3, a2, a3    \n\t"
         "aes64ks1i t2, a3, 0xa    \n\t"
         "aes64ks2  a4,t2, a4    \n\t"
         "aes64ks2  a5, a4, a5    \n\t"
         "sd a2, 96(a0)    \n\t"
         "sd a3, 104(a0)    \n\t"
         "sd a4, 112(a0)    \n\t"
         "sd a5, 120(a0)    \n\t"
         "aes64ks1i t2, a5, 3    \n\t"
         "aes64ks2  a2,t2, a2    \n\t"
         "aes64ks2  a3, a2, a3    \n\t"
         "aes64ks1i t2, a3, 0xa    \n\t"
         "aes64ks2  a4,t2, a4    \n\t"
         "aes64ks2  a5, a4, a5    \n\t"
         "sd a2, 128(a0)    \n\t"
         "sd a3, 136(a0)    \n\t"
         "sd a4, 144(a0)    \n\t"
         "sd a5, 152(a0)    \n\t"
         "aes64ks1i t2, a5, 4    \n\t"
         "aes64ks2  a2,t2, a2    \n\t"
         "aes64ks2  a3, a2, a3    \n\t"
         "aes64ks1i t2, a3, 0xa    \n\t"
         "aes64ks2  a4,t2, a4    \n\t"
         "aes64ks2  a5, a4, a5    \n\t"
         "sd a2, 160(a0)    \n\t"
         "sd a3, 168(a0)    \n\t"
         "sd a4, 176(a0)    \n\t"
         "sd a5, 184(a0)    \n\t"
         "aes64ks1i t2, a5, 5    \n\t"
         "aes64ks2  a2,t2, a2    \n\t"
         "aes64ks2  a3, a2, a3    \n\t"
         "aes64ks1i t2, a3, 0xa    \n\t"
         "aes64ks2  a4,t2, a4    \n\t"
         "aes64ks2  a5, a4, a5    \n\t"
         "sd a2, 192(a0)    \n\t"
         "sd a3, 200(a0)    \n\t"
         "sd a4, 208(a0)    \n\t"
         "sd a5, 216(a0)    \n\t"
         "aes64ks1i t2, a5, 6    \n\t"
         "aes64ks2  a2,t2, a2    \n\t"
         "aes64ks2  a3, a2, a3    \n\t"
         "sd a2, 224(a0)    \n\t"
         "sd a3, 232(a0)    \n\t"
         "ret    \n\t");
#endif /* MBEDTLS_ARCH_IS_RISCV32 */
}
#endif /* !MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH */

static void __attribute__((naked)) aes_ecb_encrypt(unsigned char ct[16],
                             const unsigned char pt[16],
                             unsigned char *rk,
                             unsigned char *ptr)
{
    (void) ct;
    (void) pt;
    (void) rk;
    (void) ptr;

#if defined(MBEDTLS_ARCH_IS_RISCV32)
    asm ("lw a4, 0(a1)    \n\t"
         "lw a5, 4(a1)    \n\t"
         "lw a6, 8(a1)    \n\t"
         "lw a7,12(a1)    \n\t"
         "lw t0, 0(a2)    \n\t"
         "lw t1, 4(a2)    \n\t"
         "lw t2, 8(a2)    \n\t"
         "lw t3, 12(a2)    \n\t"
         "xor a4, a4, t0    \n\t"
         "xor a5, a5, t1    \n\t"
         "xor a6, a6, t2    \n\t"
         "xor a7, a7, t3    \n\t"
         ".aes_enc:    \n\t"
         "lw t0, 16(a2)    \n\t"
         "lw t1, 20(a2)    \n\t"
         "lw t2, 24(a2)    \n\t"
         "lw t3, 28(a2)    \n\t"
         "aes32esmi	t0, t0, a4, 0    \n\t"
         "aes32esmi	t0, t0, a5, 1    \n\t"
         "aes32esmi	t0, t0, a6, 2    \n\t"
         "aes32esmi	t0, t0, a7, 3    \n\t"
         "aes32esmi	t1, t1, a5, 0    \n\t"
         "aes32esmi	t1, t1, a6, 1    \n\t"
         "aes32esmi	t1, t1, a7, 2    \n\t"
         "aes32esmi	t1, t1, a4, 3    \n\t"
         "aes32esmi	t2, t2, a6, 0    \n\t"
         "aes32esmi	t2, t2, a7, 1    \n\t"
         "aes32esmi	t2, t2, a4, 2    \n\t"
         "aes32esmi	t2, t2, a5, 3    \n\t"
         "aes32esmi	t3, t3, a7, 0    \n\t"
         "aes32esmi	t3, t3, a4, 1    \n\t"
         "aes32esmi	t3, t3, a5, 2    \n\t"
         "aes32esmi	t3, t3, a6, 3    \n\t"
         "lw a4, 32(a2)    \n\t"
         "lw a5, 36(a2)    \n\t"
         "lw a6, 40(a2)    \n\t"
         "lw a7, 44(a2)    \n\t"
         "addi a2, a2, 32    \n\t"
         "beq a2, a3, .aes_enc_finish    \n\t"
         "aes32esmi a4, a4, t0, 0    \n\t"
         "aes32esmi a4, a4, t1, 1    \n\t"
         "aes32esmi a4, a4, t2, 2    \n\t"
         "aes32esmi a4, a4, t3, 3    \n\t"
         "aes32esmi a5, a5, t1, 0    \n\t"
         "aes32esmi a5, a5, t2, 1    \n\t"
         "aes32esmi a5, a5, t3, 2    \n\t"
         "aes32esmi a5, a5, t0, 3    \n\t"
         "aes32esmi a6, a6, t2, 0    \n\t"
         "aes32esmi a6, a6, t3, 1    \n\t"
         "aes32esmi a6, a6, t0, 2    \n\t"
         "aes32esmi a6, a6, t1, 3    \n\t"
         "aes32esmi a7, a7, t3, 0    \n\t"
         "aes32esmi a7, a7, t0, 1    \n\t"
         "aes32esmi a7, a7, t1, 2    \n\t"
         "aes32esmi a7, a7, t2, 3    \n\t"
         "j .aes_enc    \n\t"
         ".aes_enc_finish:    \n\t"
         "aes32esi a4, a4, t0, 0    \n\t"
         "aes32esi a4, a4, t1, 1    \n\t"
         "aes32esi a4, a4, t2, 2    \n\t"
         "aes32esi a4, a4, t3, 3    \n\t"
         "aes32esi a5, a5, t1, 0    \n\t"
         "aes32esi a5, a5, t2, 1    \n\t"
         "aes32esi a5, a5, t3, 2    \n\t"
         "aes32esi a5, a5, t0, 3    \n\t"
         "aes32esi a6, a6, t2, 0    \n\t"
         "aes32esi a6, a6, t3, 1    \n\t"
         "aes32esi a6, a6, t0, 2    \n\t"
         "aes32esi a6, a6, t1, 3    \n\t"
         "aes32esi a7, a7, t3, 0    \n\t"
         "aes32esi a7, a7, t0, 1    \n\t"
         "aes32esi a7, a7, t1, 2    \n\t"
         "aes32esi a7, a7, t2, 3    \n\t"
         "sw a4, 0(a0)    \n\t"
         "sw a5, 4(a0)    \n\t"
         "sw a6, 8(a0)    \n\t"
         "sw a7, 12(a0)    \n\t"
         "ret    \n\t");
#else
    asm ("ld a5, 0(a1)    \n\t"
         "ld a6, 8(a1)    \n\t"
         ".aes_enc:    \n\t"
         "ld t2, 0(a2)    \n\t"  // Load round keys
         "ld t3, 8(a2)    \n\t"
         "ld t0, 16(a2)    \n\t"
         "ld t1, 24(a2)    \n\t"
         "xor a5, a5, t2    \n\t" // AddRoundKey
         "xor a6, a6, t3    \n\t"
         "aes64esm a7, a5, a6    \n\t"
         "aes64esm t5, a6, a5    \n\t"
         "xor a7, a7, t0    \n\t"
         "xor t5, t5, t1    \n\t"
         "aes64esm a5, a7, t5    \n\t"
         "aes64esm a6, t5, a7    \n\t"
         "addi a2, a2, 32    \n\t"
         "bne a2, a3, .aes_enc    \n\t"
         "ld t2, 0(a2)    \n\t"
         "ld t3, 8(a2)    \n\t"
         "ld t0, 16(a2)    \n\t"
         "ld t1, 24(a2)    \n\t"
         "xor a5, a5, t2    \n\t"
         "xor a6, a6, t3    \n\t"
         "ld  t2, 32(a2)    \n\t"
         "ld  t3, 40(a2)    \n\t"
         "aes64esm a7, a5, a6    \n\t"
         "aes64esm t5, a6, a5     \n\t"
         "xor a7, a7, t0    \n\t"
         "xor t5, t5, t1    \n\t"
         "aes64es a5, a7, t5    \n\t"
         "aes64es a6, t5, a7    \n\t"
         "xor a5, a5, t2    \n\t"
         "xor a6, a6, t3    \n\t"
         "sd a5, 0(a0)    \n\t"
         "sd a6, 8(a0)    \n\t"
         "ret    \n\t");
#endif /* MBEDTLS_ARCH_IS_RISCV32 */
}

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
/*
 * Key expansion of Inverse transformation for decryption
 */
static void __attribute__((naked)) aes_dec_ks_inv(unsigned char *rk,
                             const unsigned char *ck,
                             const unsigned char *rkp)
{
    (void) rk;
    (void) ck;
    (void) rkp;

#if defined(MBEDTLS_ARCH_IS_RISCV32)
    asm (".des_inv_ks_loop:    \n\t"
         "lw t0, 0(a1)    \n\t"
         "li t1, 0    \n\t"
         "aes32esi t1, t1, t0, 0    \n\t"
         "aes32esi t1, t1, t0, 1    \n\t"
         "aes32esi t1, t1, t0, 2    \n\t"
         "aes32esi t1, t1, t0, 3    \n\t"
         "li t0, 0    \n\t"
         "aes32dsmi	t0, t0, t1, 0    \n\t"
         "aes32dsmi	t0, t0, t1, 1    \n\t"
         "aes32dsmi	t0, t0, t1, 2    \n\t"
         "aes32dsmi	t0, t0, t1, 3    \n\t"
         "sw t0, 0(a0)    \n\t"
         "addi a0, a0, 4    \n\t"
         "addi a1, a1, 4    \n\t"
         "bne a1, a2, .des_inv_ks_loop    \n\t"
         "lw t0, 0(a1)    \n\t"
         "sw t0, 0(a0)    \n\t"
         "lw t0, 4(a1)    \n\t"
         "sw t0, 4(a0)    \n\t"
         "lw t0, 8(a1)    \n\t"
         "sw t0, 8(a0)    \n\t"
         "lw t0, 12(a1)    \n\t"
         "sw t0, 12(a0)    \n\t"
         "ret    \n\t");
#else
    asm (".des_inv_ks_loop:    \n\t"
         "ld a3, 0(a1)    \n\t"
         "ld a4, 8(a1)    \n\t"
         "aes64im a3, a3    \n\t"
         "aes64im a4, a4    \n\t"
         "sd a3, 0(a0)    \n\t"
         "sd a4, 8(a0)    \n\t"
         "addi a0, a0, 16    \n\t"
         "addi a1, a1, 16    \n\t"
         "bne a1, a2, .des_inv_ks_loop    \n\t"
         "ld t0, 0(a1)    \n\t"
         "sd t0, 0(a0)    \n\t"
         "ld t0, 8(a1)    \n\t"
         "sd t0, 8(a0)    \n\t"
         "ret    \n\t");
#endif /* MBEDTLS_ARCH_IS_RISCV32 */
}

static void __attribute__((naked)) aes_ecb_decrypt(unsigned char pt[16],
                             const unsigned char ct[16],
                             unsigned char *rk,
                             unsigned char *ptr)
{
    (void) pt;
    (void) ct;
    (void) rk;
    (void) ptr;

#if defined(MBEDTLS_ARCH_IS_RISCV32)
    asm ("lw a4, 0(a1)    \n\t"
         "lw a5, 4(a1)    \n\t"
         "lw a6, 8(a1)    \n\t"
         "lw a7, 12(a1)    \n\t"
         "lw t0, 0(a3)    \n\t"
         "lw t1, 4(a3)    \n\t"
         "lw t2, 8(a3)    \n\t"
         "lw t3, 12(a3)    \n\t"
         "xor a4, a4, t0    \n\t"
         "xor a5, a5, t1    \n\t"
         "xor a6, a6, t2    \n\t"
         "xor a7, a7, t3    \n\t"
         "addi a3, a3, -32    \n\t"
         ".aes_dec:    \n\t"
         "lw t0, 16(a3)    \n\t"
         "lw t1, 20(a3)    \n\t"
         "lw t2, 24(a3)    \n\t"
         "lw t3, 28(a3)    \n\t"
         "aes32dsmi	t0, t0, a4, 0    \n\t"
         "aes32dsmi	t0, t0, a7, 1    \n\t"
         "aes32dsmi	t0, t0, a6, 2    \n\t"
         "aes32dsmi	t0, t0, a5, 3    \n\t"
         "aes32dsmi	t1, t1, a5, 0    \n\t"
         "aes32dsmi	t1, t1, a4, 1    \n\t"
         "aes32dsmi	t1, t1, a7, 2    \n\t"
         "aes32dsmi	t1, t1, a6, 3    \n\t"
         "aes32dsmi	t2, t2, a6, 0    \n\t"
         "aes32dsmi	t2, t2, a5, 1    \n\t"
         "aes32dsmi	t2, t2, a4, 2    \n\t"
         "aes32dsmi	t2, t2, a7, 3    \n\t"
         "aes32dsmi	t3, t3, a7, 0    \n\t"
         "aes32dsmi	t3, t3, a6, 1    \n\t"
         "aes32dsmi	t3, t3, a5, 2    \n\t"
         "aes32dsmi	t3, t3, a4, 3    \n\t"
         "lw a4, 0(a3)    \n\t"
         "lw a5, 4(a3)    \n\t"
         "lw a6, 8(a3)    \n\t"
         "lw a7, 12(a3)    \n\t"
         "beq a2, a3, .aes_dec_finish    \n\t"
         "addi a3, a3, -32    \n\t"
         "aes32dsmi a4, a4, t0, 0    \n\t"
         "aes32dsmi a4, a4, t3, 1    \n\t"
         "aes32dsmi a4, a4, t2, 2    \n\t"
         "aes32dsmi a4, a4, t1, 3    \n\t"
         "aes32dsmi a5, a5, t1, 0    \n\t"
         "aes32dsmi a5, a5, t0, 1    \n\t"
         "aes32dsmi a5, a5, t3, 2    \n\t"
         "aes32dsmi a5, a5, t2, 3    \n\t"
         "aes32dsmi a6, a6, t2, 0    \n\t"
         "aes32dsmi a6, a6, t1, 1    \n\t"
         "aes32dsmi a6, a6, t0, 2    \n\t"
         "aes32dsmi a6, a6, t3, 3    \n\t"
         "aes32dsmi a7, a7, t3, 0    \n\t"
         "aes32dsmi a7, a7, t2, 1    \n\t"
         "aes32dsmi a7, a7, t1, 2    \n\t"
         "aes32dsmi a7, a7, t0, 3    \n\t"
         "j .aes_dec    \n\t"
         ".aes_dec_finish:    \n\t"
         "aes32dsi a4, a4, t0, 0    \n\t"
         "aes32dsi a4, a4, t3, 1    \n\t"
         "aes32dsi a4, a4, t2, 2    \n\t"
         "aes32dsi a4, a4, t1, 3    \n\t"
         "aes32dsi a5, a5, t1, 0    \n\t"
         "aes32dsi a5, a5, t0, 1    \n\t"
         "aes32dsi a5, a5, t3, 2    \n\t"
         "aes32dsi a5, a5, t2, 3    \n\t"
         "aes32dsi a6, a6, t2, 0    \n\t"
         "aes32dsi a6, a6, t1, 1    \n\t"
         "aes32dsi a6, a6, t0, 2    \n\t"
         "aes32dsi a6, a6, t3, 3    \n\t"
         "aes32dsi a7, a7, t3, 0    \n\t"
         "aes32dsi a7, a7, t2, 1    \n\t"
         "aes32dsi a7, a7, t1, 2    \n\t"
         "aes32dsi a7, a7, t0, 3    \n\t"
         "sw a4, 0(a0)    \n\t"
         "sw a5, 4(a0)    \n\t"
         "sw a6, 8(a0)    \n\t"
         "sw a7, 12(a0)    \n\t"
         "ret    \n\t");
#else
    asm ("ld a5, 0(a1)    \n\t"
        "ld a6, 8(a1)    \n\t"
        "ld t2, 32(a3)    \n\t"
        "ld t3, 40(a3)    \n\t"
        "xor     a5, a5, t2    \n\t"
        "xor     a6, a6, t3    \n\t"
        ".aes_dec:    \n\t"
        "ld t2, 16(a3)    \n\t"
        "ld t3, 24(a3)    \n\t"
        "ld t0, 0(a3)    \n\t"
        "ld t1, 8(a3)    \n\t"
        "aes64dsm a7, a5, a6    \n\t"
        "aes64dsm t6, a6, a5    \n\t"
        "xor a5, a7, t2    \n\t"
        "xor a6, t6, t3    \n\t"
        "aes64dsm a7, a5, a6    \n\t"
        "aes64dsm t6, a6, a5    \n\t"
        "xor a5, a7, t0    \n\t"
        "xor a6, t6, t1    \n\t"
        "addi a3, a3, -32    \n\t"
        "bne a2, a3, .aes_dec    \n\t"
        "ld t2, 16(a3)    \n\t"
        "ld t3, 24(a3)    \n\t"
        "ld t0, 0(a3)    \n\t"
        "ld t1, 8(a3)    \n\t"
        "aes64dsm a7, a5, a6    \n\t"
        "aes64dsm t6, a6, a5    \n\t"
        "xor a5, a7, t2    \n\t"
        "xor a6, t6, t3    \n\t"
        "aes64ds a7, a5, a6    \n\t"
        "aes64ds t6, a6, a5    \n\t"
        "xor a5, a7, t0    \n\t"
        "xor a6, t6, t1    \n\t"
        "sd a5, 0(a0)    \n\t"
        "sd a6, 8(a0)    \n\t"
        "ret    \n\t");
#endif /* MBEDTLS_ARCH_IS_RISCV32 */
}

/*
 * Compute decryption round keys from encryption round keys
 */
void mbedtls_aeszkn_inverse_key(unsigned char *invkey,
                             const unsigned char *fwdkey,
                             int nr)
{
    const unsigned char *efwdkey = fwdkey;

    memcpy(invkey, fwdkey, 16);
    efwdkey += nr * 16;
    aes_dec_ks_inv(invkey + 16, fwdkey +16, efwdkey);
}
#endif /* !MBEDTLS_BLOCK_CIPHER_NO_DECRYPT */

int mbedtls_aeszkn_setkey_enc(unsigned char *rk,
                             const unsigned char *key,
                             size_t bits)
{
    static uint8_t const rcon[] = { 0x01, 0x02, 0x04, 0x08, 0x10,
                                    0x20, 0x40, 0x80, 0x1b, 0x36 };

    switch (bits) {
        case 128: aes_128_enc_ks(rk, key, rcon); break;
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
        case 192: aes_192_enc_ks(rk, key, rcon); break;
        case 256: aes_256_enc_ks(rk, key, rcon); break;
#endif /* !MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH */
        default: return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }

    return 0;
}

/*
 * AES-ECB block en(de)cryption
 */
int mbedtls_aeszkn_crypt_ecb(mbedtls_aes_context *ctx,
                             int mode,
                             const unsigned char input[16],
                             unsigned char output[16])
{
    unsigned char *keys = (unsigned char *) (ctx->buf + ctx->rk_offset);
    unsigned char *ekeys = keys + ((ctx->nr - ((__riscv_xlen >> 6) << 1)) << 4);

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    if (mode == MBEDTLS_AES_DECRYPT) {
        aes_ecb_decrypt(output, input, keys, ekeys);
    } else
#else
    (void) mode;
#endif /* !MBEDTLS_BLOCK_CIPHER_NO_DECRYPT */
    {
        aes_ecb_encrypt(output, input, keys, ekeys);
    }

    return 0;
}
#endif /* MBEDTLS_AESZKN_HAVE_CODE */
#endif /* MBEDTLS_AESZKN_C */
