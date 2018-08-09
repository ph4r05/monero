/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#include <memory.h>
#include <stdio.h>
#ifndef _MSC_VER
#include <sys/param.h>
#endif

#include "chacha.h"
#include "common/int-util.h"
#include "warnings.h"
#include <assert.h>

/*
 * The following macros are used to obtain exact-width results.
 */
#define U8V(v) ((uint8_t)(v) & UINT8_C(0xFF))
#define U32V(v) ((uint32_t)(v) & UINT32_C(0xFFFFFFFF))

/*
 * The following macros load words from an array of bytes with
 * different types of endianness, and vice versa.
 */
#define U8TO32_LITTLE(p) SWAP32LE(((uint32_t*)(p))[0])
#define U32TO8_LITTLE(p, v) (((uint32_t*)(p))[0] = SWAP32LE(v))

#define ROTATE(v,c) (rol32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);

static const char sigma[] = "expand 32-byte k";
static const char tau[] = "expand 16-byte k";

DISABLE_GCC_AND_CLANG_WARNING(strict-aliasing)


void chacha20_init(chacha_ctx * ctx, const uint8_t * k, uint32_t kbits, const uint8_t * iv, uint32_t ivbits){
  (void)ivbits;
  const char *constants;

  ctx->input[4] = U8TO32_LITTLE(k + 0);
  ctx->input[5] = U8TO32_LITTLE(k + 4);
  ctx->input[6] = U8TO32_LITTLE(k + 8);
  ctx->input[7] = U8TO32_LITTLE(k + 12);
  if (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } else { /* kbits == 128 */
    constants = tau;
  }
  ctx->input[8] = U8TO32_LITTLE(k + 0);
  ctx->input[9] = U8TO32_LITTLE(k + 4);
  ctx->input[10] = U8TO32_LITTLE(k + 8);
  ctx->input[11] = U8TO32_LITTLE(k + 12);
  ctx->input[0] = U8TO32_LITTLE(constants + 0);
  ctx->input[1] = U8TO32_LITTLE(constants + 4);
  ctx->input[2] = U8TO32_LITTLE(constants + 8);
  ctx->input[3] = U8TO32_LITTLE(constants + 12);

  assert(ivbits == 0 || ivbits == 8 || ivbits == 12);
  if (ivbits == 8){
    ctx->input[12] = 0;
    ctx->input[13] = 0;
    ctx->input[14] = U8TO32_LITTLE(iv + 0);
    ctx->input[15] = U8TO32_LITTLE(iv + 4);
  } else if (ivbits == 12){
    ctx->input[12] = 0;
    ctx->input[13] = U8TO32_LITTLE(iv + 0);
    ctx->input[14] = U8TO32_LITTLE(iv + 4);
    ctx->input[15] = U8TO32_LITTLE(iv + 8);
  }
}

static void chacha_encrypt(chacha_ctx * ctx, const uint8_t * data, uint8_t * cipher, uint32_t length, unsigned rounds){
  uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  uint32_t j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
  uint8_t *ctarget = 0;
  uint8_t tmp[64];
  int i;

  if (!length) return;

  j0 = ctx->input[0];
  j1 = ctx->input[1];
  j2 = ctx->input[2];
  j3 = ctx->input[3];
  j4 = ctx->input[4];
  j5 = ctx->input[5];
  j6 = ctx->input[6];
  j7 = ctx->input[7];
  j8 = ctx->input[8];
  j9 = ctx->input[9];
  j10 = ctx->input[10];
  j11 = ctx->input[11];
  j12 = ctx->input[12];
  j13 = ctx->input[13];
  j14 = ctx->input[14];
  j15 = ctx->input[15];

  for (;;) {
    if (length < 64) {
      memcpy(tmp, data, length);
      data = tmp;
      ctarget = cipher;
      cipher = tmp;
    }
    x0  = j0;
    x1  = j1;
    x2  = j2;
    x3  = j3;
    x4  = j4;
    x5  = j5;
    x6  = j6;
    x7  = j7;
    x8  = j8;
    x9  = j9;
    x10 = j10;
    x11 = j11;
    x12 = j12;
    x13 = j13;
    x14 = j14;
    x15 = j15;
    for (i = rounds;i > 0;i -= 2) {
      QUARTERROUND( x0, x4, x8,x12)
      QUARTERROUND( x1, x5, x9,x13)
      QUARTERROUND( x2, x6,x10,x14)
      QUARTERROUND( x3, x7,x11,x15)
      QUARTERROUND( x0, x5,x10,x15)
      QUARTERROUND( x1, x6,x11,x12)
      QUARTERROUND( x2, x7, x8,x13)
      QUARTERROUND( x3, x4, x9,x14)
    }
    x0  = PLUS( x0, j0);
    x1  = PLUS( x1, j1);
    x2  = PLUS( x2, j2);
    x3  = PLUS( x3, j3);
    x4  = PLUS( x4, j4);
    x5  = PLUS( x5, j5);
    x6  = PLUS( x6, j6);
    x7  = PLUS( x7, j7);
    x8  = PLUS( x8, j8);
    x9  = PLUS( x9, j9);
    x10 = PLUS(x10,j10);
    x11 = PLUS(x11,j11);
    x12 = PLUS(x12,j12);
    x13 = PLUS(x13,j13);
    x14 = PLUS(x14,j14);
    x15 = PLUS(x15,j15);

    x0  = XOR( x0,U8TO32_LITTLE(data + 0));
    x1  = XOR( x1,U8TO32_LITTLE(data + 4));
    x2  = XOR( x2,U8TO32_LITTLE(data + 8));
    x3  = XOR( x3,U8TO32_LITTLE(data + 12));
    x4  = XOR( x4,U8TO32_LITTLE(data + 16));
    x5  = XOR( x5,U8TO32_LITTLE(data + 20));
    x6  = XOR( x6,U8TO32_LITTLE(data + 24));
    x7  = XOR( x7,U8TO32_LITTLE(data + 28));
    x8  = XOR( x8,U8TO32_LITTLE(data + 32));
    x9  = XOR( x9,U8TO32_LITTLE(data + 36));
    x10 = XOR(x10,U8TO32_LITTLE(data + 40));
    x11 = XOR(x11,U8TO32_LITTLE(data + 44));
    x12 = XOR(x12,U8TO32_LITTLE(data + 48));
    x13 = XOR(x13,U8TO32_LITTLE(data + 52));
    x14 = XOR(x14,U8TO32_LITTLE(data + 56));
    x15 = XOR(x15,U8TO32_LITTLE(data + 60));

    j12 = PLUSONE(j12);
    if (!j12)
    {
      j13 = PLUSONE(j13);
      /* stopping at 2^70 bytes per iv is user's responsibility */
    }

    U32TO8_LITTLE(cipher +  0,x0);
    U32TO8_LITTLE(cipher +  4,x1);
    U32TO8_LITTLE(cipher +  8,x2);
    U32TO8_LITTLE(cipher + 12,x3);
    U32TO8_LITTLE(cipher + 16,x4);
    U32TO8_LITTLE(cipher + 20,x5);
    U32TO8_LITTLE(cipher + 24,x6);
    U32TO8_LITTLE(cipher + 28,x7);
    U32TO8_LITTLE(cipher + 32,x8);
    U32TO8_LITTLE(cipher + 36,x9);
    U32TO8_LITTLE(cipher + 40,x10);
    U32TO8_LITTLE(cipher + 44,x11);
    U32TO8_LITTLE(cipher + 48,x12);
    U32TO8_LITTLE(cipher + 52,x13);
    U32TO8_LITTLE(cipher + 56,x14);
    U32TO8_LITTLE(cipher + 60,x15);

    if (length <= 64) {
      if (length < 64) {
        for (i = 0;i < (int)length;++i) ctarget[i] = cipher[i];
      }
      ctx->input[12] = j12;
      ctx->input[13] = j13;
      return;
    }
    length -= 64;
    cipher += 64;
    data += 64;
  }
}

void chacha20_encrypt(chacha_ctx * ctx, const uint8_t * m, uint8_t * c, uint32_t bytes){
  chacha_encrypt(ctx, m, c, bytes, 20);
}

static void chacha(unsigned rounds, const void* data, size_t length, const uint8_t* key, const uint8_t* iv, char* cipher) {
  chacha_ctx ctx;
  chacha20_init(&ctx, key, 256, iv, 8);
  chacha_encrypt(&ctx, data, (uint8_t *) cipher, (uint32_t) length, rounds);
}

void chacha8(const void* data, size_t length, const uint8_t* key, const uint8_t* iv, char* cipher)
{
  chacha(8, data, length, key, iv, cipher);
}

void chacha20(const void* data, size_t length, const uint8_t* key, const uint8_t* iv, char* cipher)
{
  chacha(20, data, length, key, iv, cipher);
}
