/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

//#define DEBUG

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#define __USE_GNU
#include <sched.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <semaphore.h>
#include <getopt.h>
#include "hpre_test_sample.h"
#include "test_hisi_hpre.h"
#include "../../include/wd.h"
#include "../../include/wd_rsa.h"
#include "../../include/wd_dh.h"
#include "../../include/wd_ecc.h"
#include "../../include/drv/wd_ecc_drv.h"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#define HPRE_TST_PRT		printf
#define HPRE_TST_MAX_Q		1
#define HPRE_PADDING_SZ		16
#define TEST_MAX_THRD		256
#define MAX_TRY_TIMES		10000
#define LOG_INTVL_NUM		8
#define WD_RSA_CTX_MSG_NUM		64
#define WD_DH_CTX_MSG_NUM		64
#define DH_GENERATOR_2			2
#define DH_GENERATOR_5			5
#define TEST_CNT		10
#define INVALID_LEN		0xFFFFFFFF

typedef unsigned int u32;

pthread_mutex_t mute;

struct test_hpre_pthread_dt {
	int cpu_id;
	enum alg_op_type op_type;
	const char *alg_name;
	int thread_num;
	float perf;
	struct timeval start_tval;
	u32 send_task_num;
	u32 recv_task_num;
};

enum ecc_msg_type {
	MSG_PLAINTEXT,
	MSG_DIGEST,
	MSG_CIPHERTEXT
};

enum ecc_rand_type {
	RAND_NON,
	RAND_CB,
	RAND_PARAM
};

enum dh_check_index {
	DH_INVALID,
	DH_ALICE_PUBKEY,
	DH_BOB_PUBKEY,
	DH_ALICE_PRIVKEY
};

enum ecc_hash_type {
	HASH_NON,
	HASH_SM3,
	HASH_SHA1,
	HASH_SHA224,
	HASH_SHA256,
	HASH_SHA384,
	HASH_SHA512,
	HASH_MD4,
	HASH_MD5

};

struct rsa_async_tag {
	handle_t sess;
	int thread_id;
	int cnt;
	struct test_hpre_pthread_dt *thread_info;
};

struct dh_user_tag_info {
	u32 op;
	int pid;
	int thread_id;
	void *test_ctx;
	void *thread_data;
};

struct async_test_openssl_param {
	EVP_PKEY *rsa;
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *e;
	BIGNUM *n;
	BIGNUM *d;
	BIGNUM *dp;
	BIGNUM *dq;
	BIGNUM *qinv;
	void *ssl_verify_result;
	void *ssl_sign_result;
	void *plantext;
	int size;
};

struct ecc_curve_tbl {
	const char *name;
	unsigned int nid;
	unsigned int curve_id;
};

struct hpre_test_config {
	__u32 key_bits;
	__u32 times;
	__u32 seconds;
	__u8 check;
	__u8 perf_test;
	__u8 soft_test;
	__u8 use_env;
	__u8 with_log;
	__u8 data_from; // 0 - openssl generate 1 - sample data
	__u8 trd_num;
	__u8 msg_type; // 0-plaintext 1-digest 2-ciphertext;
	__u8 rand_type; // 0-non 1-cb 2-param;
	__u8 hash_type;
	__u32 msg_len;
	__u32 id_len;
	__u32 k_len;
	__u64 core_mask[2];
	char alg_mode[10];
	char trd_mode[10];
	char op[20];
	char curve[20];
	char dev_path[PATH_STR_SIZE];
};

static struct hpre_test_config g_config = {
	.key_bits = 1024,
	.times = 100,
	.seconds = 0,
	.trd_num = 2,
	.use_env = 0,
	.msg_type = MSG_PLAINTEXT,
	.msg_len = INVALID_LEN,
	.id_len = INVALID_LEN,
	.k_len = INVALID_LEN,
	.hash_type = HASH_SM3,
	.rand_type = RAND_CB,
		.check = 1,
	.data_from = 0,
	.perf_test = 0,
	.with_log = 0,
	.soft_test = 0,
	.core_mask = {0, 0},
	.trd_mode = "sync",
	.op = "rsa-gen",
	.alg_mode = "com",
	.curve = "secp256K1",
	.dev_path = "/dev/hisi_hpre-0",
};

static volatile int asyn_thread_exit = 0;
static pthread_t system_test_thrds[TEST_MAX_THRD];
static struct test_hpre_pthread_dt test_thrds_data[TEST_MAX_THRD];
static struct async_test_openssl_param ssl_params;
struct wd_ctx_config g_ctx_cfg;
static __thread u32 g_is_set_prikey; // ecdh used
static __thread u32 g_is_set_pubkey; // ecc used
static pthread_spinlock_t g_lock;

static bool is_exit(struct test_hpre_pthread_dt *pdata);

struct ecc_curve_tbl ecc_curve_tbls[] = {
	{"secp128R1", 706, WD_SECP128R1},
	{"secp192K1", 711, WD_SECP192K1},
	{"secp224R1", 712, WD_SECP224R1},
	{"secp256K1", 714, WD_SECP256K1},
	{"brainpoolP320R1", 929, WD_BRAINPOOLP320R1},
	{"secp384R1", 715, WD_SECP384R1},
	{"secp521R1", 716, WD_SECP521R1},
	{"null", 0, 0},
};

enum dh_test_item {
	TEST_ITEM_INVALID,
	SW_GENERATE_KEY,
	SW_COMPUTE_KEY,
	HW_GENERATE_KEY,
	HW_COMPUTE_KEY,
};

struct hpre_dh_test_ctx_setup {
	const void *x;
	const void *p;
	const void *g;
	const void *except_pub_key;
	const void *pub_key;
	const void *share_key;
	u32 x_size;
	u32 p_size;
	u32 g_size;
	u32 pub_key_size;
	u32 share_key_size;
	u32 except_pub_key_size;
	u32 op_type;
	u32 generator;
	u32 key_bits;
	u32 key_from; //0 - Openssl  1 - Designed
	handle_t sess;
};

struct hpre_dh_sw_opdata {
	BIGNUM *except_pub_key;
	unsigned char *pub_key;
	u32 pub_key_size;
	unsigned char *share_key;
	u32 share_key_size;
};

struct hpre_dh_test_ctx {
	void *priv;
	void *req;
	unsigned char *cp_share_key;
	u32 cp_share_key_size;
	unsigned char *cp_pub_key;
	u32 cp_pub_key_size;
	u32 op;
	u32 key_size;
	void *pool;
};

struct hpre_rsa_test_key_in {
	void *e;
	void *p;
	void *q;
	u32 e_size;
	u32 p_size;
	u32 q_size;
	void *data[];
};

#define X25519_KEYLEN	32
#define X448_KEYLEN		56
#define ED448_KEYLEN         57
#define MAX_KEYLEN  ED448_KEYLEN


typedef struct {
	unsigned char pubkey[MAX_KEYLEN];
	unsigned char *privkey;
} ECX_KEY;



/********************  ECC  *********************/
enum ecc_test_item {
	ECC_TEST_ITEM_INVALID,
	ECDH_SW_GENERATE,
	ECDH_SW_COMPUTE,
	ECDH_HW_GENERATE,
	ECDH_HW_COMPUTE,
	ECC_SW_SIGN,
	ECC_SW_VERF,
	ECC_HW_SIGN,
	ECC_HW_VERF,
	SM2_SW_SIGN,
	SM2_SW_VERF,
	SM2_HW_SIGN,
	SM2_HW_VERF,
	SM2_HW_ENC,
	SM2_HW_DEC,
	SM2_SW_ENC,
	SM2_SW_DEC,
	SM2_SW_KG,
	SM2_HW_KG,
	ECC_TEST_ITEM_MAX
};

struct ecc_test_ctx_setup {
	void *except_pub_key; // use in ecdh phase 2
	const void *pub_key; // use in ecdh phase 1
	const void *share_key; // use in ecdh phase 2
	const void *degist; //ecdsa sign in
	const void *k; //ecdsa sign in
	const void *rp; //ecdsa sign in
	const void *sign; // ecdsa sign out or verf in
	const void *priv_key; // use in ecdsa sign
	void *msg; // sm2 plaintext,ciphertext or digest input
	const void *userid; // sm2 user id
	const void *ciphertext; // sm2 ciphertext
	const void *plaintext; // sm2 plaintext
	u32 key_size;
	u32 share_key_size;
	u32 except_pub_key_size;
	u32 degist_size;
	u32 k_size;
	u32 rp_size;
	u32 sign_size;
	u32 priv_key_size;
	u32 pub_key_size;
	u32 msg_size;
	u32 userid_size;
	u32 ciphertext_size;
	u32 plaintext_size;
	u32 op_type;
	u32 key_bits;
	u32 key_from; //0 - Openssl  1 - Designed
	u32 nid; //openssl ecc nid
	u32 curve_id; // WD ecc curve_id
	handle_t sess;
	void *openssl_handle;
};

struct ecc_test_ctx {
	void *priv;
	void *priv1; // openssl key handle used in hpre sign and openssl verf
	void *req;
	unsigned char *cp_share_key;
	u32 cp_share_key_size;
	unsigned char *cp_pub_key;
	u32 cp_pub_key_size;
	u32 key_size;
	/* ecdsa sign*/
#define MAX_SIGN_LEN 200
	unsigned char cp_sign[MAX_SIGN_LEN];
#define MAX_ENC_LEN 8192
	unsigned char cp_enc[MAX_ENC_LEN];
	size_t cp_sign_size;
	size_t cp_enc_size;
	__u8 is_x25519_x448;
	struct ecc_test_ctx_setup setup;
};

struct ecdh_sw_opdata {
	void *except_pub_key;
	unsigned char *pub_key;
	u32 pub_key_size;
	unsigned char *share_key;
	u32 share_key_size;

	/* ecdsa sign / verf */
	unsigned char *except_e;
	u32 except_e_size;
	BIGNUM *except_kinv;
	BIGNUM *except_rp;
	unsigned char *sign; // sign out or verf in
	u32 sign_size;

};

static char *ecc_op_str[ECC_TEST_ITEM_MAX] = {
	"invalid_op",
	"xdh sw gen",
	"xdh sw compute",
	"xdh hw gen",
	"xdh hw compute",
	"ecdsa sw sign",
	"ecdsa sw verf",
	"ecdsa hw sign",
	"ecdsa hw verf",
	"sm2 sw sign",
	"sm2 sw verf",
	"sm2 hw sign",
	"sm2 hw verf",
	"sm2 sw enc",
	"sm2 sw dec",
	"sm2 hw enc",
	"sm2 hw dec",
	"sm2 sw kg",
	"sm2 hw kg",
};

static __thread struct hpre_rsa_test_key_in *rsa_key_in = NULL;

#define EVP_DigestSignUpdate(a, b, c)	EVP_DigestUpdate(a, b, c)
#define EVP_DigestVerifyUpdate(a, b, c)	EVP_DigestUpdate(a, b, c)

/* Internal OpenSSL 1.1.1 function - not in public headers */
void EVP_MD_CTX_set_pkey_ctx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pctx);

static RAND_METHOD fake_rand;
static const RAND_METHOD *saved_rand;
static uint8_t *fake_rand_bytes = NULL;
static size_t fake_rand_bytes_offset = 0;
static size_t fake_rand_size = 0;
static int get_faked_bytes(__u8 *buf, int num)
{
	int i;

	if (fake_rand_bytes == NULL)
		return saved_rand->bytes(buf, num);

	for (i = 0; i != num; ++i)
		buf[i] = fake_rand_bytes[fake_rand_bytes_offset + i];

	fake_rand_bytes_offset += num;

	return 1;
}

static int start_fake_rand(const char *hex_bytes)
{
	/* save old rand method */
	if (!(saved_rand = RAND_get_rand_method()))
		return 0;

	fake_rand = *saved_rand;
	/* use own random function */
	fake_rand.bytes = get_faked_bytes;

	fake_rand_bytes = OPENSSL_hexstr2buf(hex_bytes, NULL);
	fake_rand_bytes_offset = 0;
	fake_rand_size = strlen(hex_bytes) / 2;

	/* set new RAND_METHOD */
	RAND_set_rand_method(&fake_rand);

	return 1;
}

static void print_data(void *ptr, int size, const char *name)
{
	__u32 i = 0;
	__u8* p = ptr;

	printf("\n%s:start_addr=%p, size %d\n", name, ptr, size);
	for (i = 1; i <= size; i++) {
		printf("0x%02x ", p[i - 1]);
		if (i % 16 == 0)
			printf("\n");
	}
	printf("\n");
}

static int crypto_bin_to_hpre_bin(char *dst, const char *src,
				int b_size, int d_size)
{
	int i = d_size - 1;
	char *buff = NULL;
	char *src_tmp;
	int j = 0;

	if (!dst || !src || b_size <= 0 || d_size <= 0) {
		WD_ERR("crypto bin to hpre bin params err!\n");
		return -WD_EINVAL;
	}

	if (b_size < d_size) {
		WD_ERR("crypto bin to hpre bin param data is too long!\n");
		return  -WD_EINVAL;
	}

	if (b_size == d_size)
		return WD_SUCCESS;

	if (dst == src) {
		buff = malloc(d_size);
		if (!buff)
			return  -WD_ENOMEM;
		memcpy(buff, src, d_size);
		src_tmp = buff;
	} else {
		src_tmp = (void *)src;
	}

	for (j = b_size - 1; j >= 0; j--, i--) {
		if (i >= 0)
			dst[j] = src_tmp[i];
		else
			dst[j] = 0;
	}

	if (buff)
		free(buff);

	return WD_SUCCESS;
}

static __u8 is_async_test(__u32 opType)
{
	if (opType == RSA_KEY_GEN || opType == RSA_PUB_EN || opType == RSA_PRV_DE ||
		opType == DH_GEN || opType == DH_COMPUTE ||
		opType == ECDSA_SIGN || opType == ECDSA_VERF ||
		opType == SM2_SIGN || opType == SM2_VERF ||
		opType == SM2_ENC || opType == SM2_DEC || opType == SM2_KG ||
		opType == ECDH_GEN || opType == ECDH_COMPUTE ||
		opType == X25519_GEN || opType == X25519_COMPUTE ||
		opType == X448_GEN || opType == X448_COMPUTE)
		return false;

	return true;
}

static void evp_sign_to_hpre_bin(char *evp, size_t *evp_size, __u32 ksz)
{
	__u32 r_sz = evp[3];
	__u32 s_sz = evp[4 + r_sz + 1];
	char *r_data = evp + 4;
	char *s_data = evp + 4 + r_sz + 2;
	char tmp[MAX_SIGN_LEN] = {0};

	if (r_sz >= ksz)
		memcpy(tmp, r_data + r_sz - ksz, ksz);
	else if (r_sz < ksz)
		memcpy(tmp + ksz - r_sz, r_data, r_sz);

	if (s_sz >= ksz)
		memcpy(tmp + ksz, s_data + s_sz - ksz, ksz);
	else if (s_sz < ksz)
		memcpy(tmp + ksz + ksz - s_sz, s_data, s_sz);

	memset(evp, 0, *evp_size);
	memcpy(evp, tmp, 2 * ksz);
	*evp_size = 2 * ksz;
}

static int hpre_bin_sign_to_evp(char *evp, char *bin, __u32 ksz)
{
	char tmp[MAX_SIGN_LEN] = {0};
	char head[2] = {0x30, 0x44};
	char r_head[3] = {0x02, 0x20};
	char s_head[3] = {0x02, 0x20};
	__u8 head_bytes = 2;
	__u8 r_head_bytes = 2;
	__u8 s_head_bytes = 2;
	__u32 total_len = 0x46;
	__u8 r_size = ksz;
	__u8 s_size = ksz;
	__u8 val;
	int i;

	i = 0;
	val = bin[i];
	while (!val && i++ < ksz - 1)
		val = bin[i];
	r_size -= i;
	total_len -= i;
	head[1] -= i;
	r_head[1] -= i;
	if (bin[i] & 0x80) {
		r_head_bytes = 3;
		total_len += 1;
		head[1]++;
		r_head[1]++;
	}

	i = 0;
	val = bin[ksz + i];
	while (!val && i++ < ksz - 1)
		val = bin[ksz + i];
	s_size -= i;
	total_len -= i;
	head[1] -= i;
	s_head[1] -= i;
	if (bin[ksz + i] & 0x80) {
		s_head_bytes = 3;
		total_len += 1;
		head[1]++;
		s_head[1]++;
	}

	memcpy(tmp, head, head_bytes);
	memcpy(tmp + head_bytes, r_head, r_head_bytes);
	memcpy(tmp + head_bytes + r_head_bytes, bin + ksz - r_size, r_size);
	memcpy(tmp + head_bytes + r_head_bytes + r_size, s_head, s_head_bytes);
	memcpy(tmp + head_bytes + r_head_bytes + r_size + s_head_bytes, bin + 2 * ksz - s_size, s_size);
	memcpy(evp, tmp, total_len);

	return total_len;
}

static int sm2_enc_in_bin_to_evp(char *evp, char *bin, __u32 m_len, __u32 ksz, __u32 c3_sz)

{
        char *tmp;
        char *c1 = bin;
        char *c2 = bin + ksz * 2;
        char *c3 = c2 + m_len;
        __u32 total_len;
        char head[4] = {0x30, 0x00};
        char c1x_head[3] = {0x02, 0x20};
        char c1y_head[3] = {0x02, 0x20, 0x00};
        char c3_head[3] = {0x04, 0x20};
        char c2_head[4] = {0x04, 0x00};
        __u8 head_bytes = 2;
        __u8 c1x_head_bytes = 2;
        __u8 c1y_head_bytes = 2;
        __u8 c3_head_bytes = 2;
        __u8 c2_head_bytes = 2;
        __u8 c1x_size = ksz;
        __u8 c1y_size = ksz;
        __u8 c3_size = c3_sz;
        __u8 val;
        int i;

        tmp = malloc(MAX_ENC_LEN);
        if (!tmp) {
                HPRE_TST_PRT("%s: malloc fail\n", __func__);
                return 0;
        }

        if (m_len > 127) {
                c2_head_bytes = 4;
                c2_head[1] = 0x82;
                c2_head[2] = m_len >> 8;
                c2_head[3] = m_len & 0xff;
        } else {
                c2_head[1] = m_len;
        }

        c3_head[1] = c3_sz;
        total_len = 64 + c3_sz + head_bytes + c1x_head_bytes + c1y_head_bytes +
                c3_head_bytes + c2_head_bytes + m_len;

        i = 0;
        val = bin[i];
        while (!val && i++ < ksz - 1) {
                val = bin[i];
        }

        c1x_size -= i;
        total_len -= i;
        c1x_head[1] -= i;
        if (bin[i] & 0x80) {
                c1x_head_bytes = 3;
                total_len += 1;
                c1x_head[1]++;
        }

        i = 0;
        val = bin[i + ksz];
        while (!val && i++ < ksz - 1) {
                val = bin[i + ksz];
        }

        c1y_size -= i;
        total_len -= i;
        c1y_head[1] -= i;
        if (bin[i + ksz] & 0x80) {
                c1y_head_bytes = 3;
                total_len += 1;
                c1y_head[1]++;
        }

        if (total_len >= 130) {
                head_bytes = 4;
                total_len += 2;
                head[1] = 0x82;
                head[2] = (total_len - 4) >> 8;
                head[3] = (total_len - 4) & 0xff;
        } else {
                head[1] = (total_len - 2) & 0xff;
        }

        memcpy(tmp, head, head_bytes); // head
        memcpy(tmp + head_bytes, c1x_head, c1x_head_bytes); // c1 x head
        memcpy(tmp + head_bytes + c1x_head_bytes, bin + ksz - c1x_size, c1x_size); // c1 x
        memcpy(tmp + head_bytes + c1x_head_bytes + c1x_size, c1y_head, c1y_head_bytes); //c1 y head
        memcpy(tmp + head_bytes + c1x_head_bytes + c1x_size + c1y_head_bytes, c1 + 2 * ksz - c1y_size, c1y_size); // c1 y
        memcpy(tmp + head_bytes + c1x_head_bytes + c1x_size + c1y_head_bytes + c1y_size, c3_head, c3_head_bytes); //c3 head
        memcpy(tmp + head_bytes + c1x_head_bytes + c1x_size + c1y_head_bytes + c1y_size + c3_head_bytes, c3, c3_size); //c3 head
        memcpy(tmp + head_bytes + c1x_head_bytes + c1x_size + c1y_head_bytes + c1y_size + c3_head_bytes + c3_size, c2_head, c2_head_bytes); //c2 head
        memcpy(tmp + head_bytes + c1x_head_bytes + c1x_size + c1y_head_bytes + c1y_size + c3_head_bytes + c3_size + c2_head_bytes, c2, m_len); //c2
        memcpy(evp, tmp, total_len);
        //print_data(evp, total_len, "evp");

        free(tmp);
        return total_len;
}

__u32 get_big_endian_value(char *buf, __u32 size)
{
	__u32 ret = 0;
	char tmp[4] = {0};

	if (size == 1) {
		ret = buf[0];
	} else if (size == 2) {
		tmp[0] = buf[1];
		tmp[1] = buf[0];
		ret = *(unsigned short *)tmp;
	}

	return ret;
 }

static int evp_to_wd_crypto(char *evp, size_t *evp_size, __u32 ksz, __u8 op_type)
{
        __u32 total_len = 0;
        __u32 l_sz = 0;
        __u8 *data;
        __u32 d_sz = 0;
        __u32 cur_len = 0;
        __u32 out_len = 0;
        __u32 i = 0;
        char *buf;
        char *buf_backup;

        buf = malloc(*evp_size + 64); /* may crypto bin len > evp_size */
        if (!buf) {
                HPRE_TST_PRT("%s: malloc fail\n", __func__);
                return -1;
        }

        memset(buf, 0, *evp_size);
        buf_backup = buf;
        cur_len += 1;
        if (evp[cur_len] & 0x80) {
                l_sz = evp[cur_len] & 0x7f;
                cur_len += 1;
        } else {
                l_sz = 1;
        }

        if (l_sz == 1)
                total_len = evp[cur_len];
        else if (l_sz == 2)
                total_len = get_big_endian_value(&evp[cur_len], 2);
        cur_len += l_sz;

        while (cur_len < *evp_size) {
                if (evp[cur_len] == 0x2) {
                        cur_len += 1;
                        l_sz = 1;
                } else if (evp[cur_len] == 0x4) {
                        cur_len += 1;
                        if (evp[cur_len] & 0x80) {
                                l_sz = evp[cur_len] & 0x7f;
                                cur_len += 1;
                        } else {
                                l_sz = 1;
                        }
                }

                if (l_sz == 1)
                        d_sz = evp[cur_len];
                else if (l_sz == 2)
                        d_sz = get_big_endian_value(&evp[cur_len], 2);
                cur_len += l_sz;

                data = (void *)&evp[cur_len];
                if (!data[0] && i < 2) { //c3 c2 no need
                        cur_len += 1;
                        d_sz -= 1;
                }

                if (op_type == SM2_HW_ENC && cur_len + d_sz >= *evp_size) {
                        memcpy(buf, &evp[cur_len], d_sz);
                        buf += d_sz;
                        cur_len += d_sz;
                        out_len += d_sz;
                } else if (op_type == SM2_HW_ENC && i == 2) {
                        memcpy(buf, &evp[cur_len], d_sz);
                        buf += d_sz;
                        cur_len += d_sz;
                        out_len += d_sz;
                } else {
                        memcpy(buf + ksz - d_sz, &evp[cur_len], d_sz);
                        buf += ksz;
                        cur_len += ksz;
                        out_len += ksz;
                }
                i++;
        }

        memcpy(evp, buf_backup, out_len);
        *evp_size = out_len;
        free(buf_backup);

        return total_len;
}

static handle_t hpre_sched_init(handle_t h_sched_ctx, void *sched_param)
{
	return (handle_t)0;
}

static __u32 hpre_pick_next_ctx(handle_t sched_ctx,
	void *sched_key, const int sched_mode)
{
	static int last_ctx = 0;

	if (!strncmp(g_config.trd_mode, "async", 5))
		return 0;

	pthread_spin_lock(&g_lock);
	if (++last_ctx == g_ctx_cfg.ctx_num)
		last_ctx = 0;
	pthread_spin_unlock(&g_lock);

	return last_ctx;
}

int rsa_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	int ret;
	struct wd_ctx *ctxs;
	int i;

	while (1) {
		for (i = 0; i < g_ctx_cfg.ctx_num; i++) {
			ctxs = &g_ctx_cfg.ctxs[i];
			if (ctxs->ctx_mode == CTX_MODE_ASYNC) {
				ret = wd_rsa_poll_ctx(i, 1, count);
				if (ret != -EAGAIN && ret < 0) {
					HPRE_TST_PRT("fail poll ctx %d!\n", i);
					return ret;
				}
			}
		}

		break;
	}

	return 0;
}

static int dh_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	int ret;
	struct wd_ctx *ctxs;
	int i;

	while (1) {
		for (i = 0; i < g_ctx_cfg.ctx_num; i++) {
			ctxs = &g_ctx_cfg.ctxs[i];
			if (ctxs->ctx_mode == CTX_MODE_ASYNC) {
				ret = wd_dh_poll_ctx(i, 1, count);
				if (ret != -EAGAIN && ret < 0) {
					HPRE_TST_PRT("fail poll ctx %d!\n", i);
					return ret;
				}
			}
		}
		break;
	}

	return 0;
}

static int ecc_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	int ret;
	struct wd_ctx *ctxs;
	int i;

	while (1) {
		for (i = 0; i < g_ctx_cfg.ctx_num; i++) {
			ctxs = &g_ctx_cfg.ctxs[i];
			if (ctxs->ctx_mode == CTX_MODE_ASYNC) {
				ret = wd_ecc_poll_ctx(i, 1, count);
				if (ret != -EAGAIN && ret < 0) {
					HPRE_TST_PRT("fail poll ctx %d!\n", i);
					return ret;
				}
			}
		}
		break;
	}

	return 0;
}

static __u32 get_alg_op_type(enum alg_op_type op_type)
{
	__u32 value = 0;

	switch (op_type) {
	case RSA_KEY_GEN:
	case RSA_ASYNC_GEN:
		value = WD_RSA_GENKEY;
		break;
	case RSA_PUB_EN:
	case RSA_ASYNC_EN:
		value = WD_RSA_VERIFY;
		break;
	case RSA_PRV_DE:
	case RSA_ASYNC_DE:
		value = WD_RSA_SIGN;
		break;
	default:
		break;
	}

	return value;
}

static struct uacce_dev_list *get_uacce_dev_by_alg(struct uacce_dev_list *list,
						   char *alg)
{
	while (list) {
		if (!strncmp(alg, list->dev->char_dev_path, strlen(alg)))
			break;
		else
			list = list->next;
	}

	return list;

}

static int env_init(__u32 op_type)
{
	if (op_type > HPRE_ALG_INVLD_TYPE && op_type < MAX_RSA_ASYNC_TYPE)
		return wd_rsa_env_init(NULL);
	else if (op_type > MAX_RSA_ASYNC_TYPE && op_type < MAX_DH_TYPE)
		return wd_dh_env_init(NULL);
	else if (op_type > MAX_DH_TYPE && op_type < MAX_ECDH_TYPE)
		return wd_ecc_env_init(NULL);
	else if (op_type > MAX_ECDH_TYPE && op_type < MAX_ECDSA_TYPE)
		return wd_ecc_env_init(NULL);
	else if (op_type >= SM2_SIGN && op_type <= SM2_ASYNC_KG)
		return wd_ecc_env_init(NULL);
	else {
		HPRE_TST_PRT("op_type = %u error\n", op_type);
		return -ENODEV;
	}
}

static int init_hpre_global_config(__u32 op_type)
{
	struct uacce_dev_list *list = NULL;
	struct uacce_dev_list *uacce_node;
	struct wd_ctx *ctx_attr;
	struct wd_sched sched;
	int ctx_num = g_config.trd_num;
	int ret = 0;
	int j;

	if (g_config.use_env)
		return env_init(op_type);

#ifdef DEBUG
	HPRE_TST_PRT("request ctx[%d] from %s!\n", ctx_num, g_config.dev_path);
#endif

	if (op_type > HPRE_ALG_INVLD_TYPE && op_type < MAX_RSA_ASYNC_TYPE)
		list = wd_get_accel_list("rsa");
	else if (op_type > MAX_RSA_ASYNC_TYPE && op_type < MAX_DH_TYPE)
		list = wd_get_accel_list("dh");
	else if (op_type > MAX_DH_TYPE && op_type < MAX_ECDH_TYPE)
		list = wd_get_accel_list("ecdh");
	else if (op_type > MAX_ECDH_TYPE && op_type < MAX_ECDSA_TYPE)
		list = wd_get_accel_list("ecdsa");
	else if (op_type >= SM2_SIGN && op_type <= SM2_ASYNC_KG)
		list = wd_get_accel_list("sm2");
	else
		HPRE_TST_PRT("op_type = %u error\n", op_type);
	if (!list)
		return -ENODEV;

	uacce_node = get_uacce_dev_by_alg(list, g_config.dev_path);
	if (!uacce_node) {
		HPRE_TST_PRT("dev_path %s error\n", g_config.dev_path);
		return -ENODEV;
	}

	ctx_attr = malloc(ctx_num * sizeof(struct wd_ctx));
	if (!ctx_attr) {
		HPRE_TST_PRT("malloc ctx_attr memory fail!\n");
		return -ENOMEM;
	}
	memset(ctx_attr, 0, ctx_num * sizeof(struct wd_ctx));

	for (j = 0; j < ctx_num; j++) {
		ctx_attr[j].ctx = wd_request_ctx(uacce_node->dev);
		if (!ctx_attr[j].ctx) {
			HPRE_TST_PRT("failed to request ctx!\n");
			return -1;
		}
		ctx_attr[j].ctx_mode = is_async_test(op_type);
		ctx_attr[j].op_type = get_alg_op_type(op_type);
	}

	g_ctx_cfg.ctx_num = ctx_num;
	g_ctx_cfg.ctxs = ctx_attr;
	sched.name = "hpre-sched-0";
	sched.pick_next_ctx = hpre_pick_next_ctx;
	sched.sched_init = hpre_sched_init;
	if (op_type > HPRE_ALG_INVLD_TYPE && op_type < MAX_RSA_ASYNC_TYPE) {
		sched.poll_policy = rsa_poll_policy;
		ret = wd_rsa_init(&g_ctx_cfg, &sched);
	} else if (op_type > MAX_RSA_ASYNC_TYPE && op_type < MAX_DH_TYPE) {
		sched.poll_policy = dh_poll_policy;
		ret = wd_dh_init(&g_ctx_cfg, &sched);
	} else {
		sched.poll_policy = ecc_poll_policy;
		ret = wd_ecc_init(&g_ctx_cfg, &sched);
	}

	if (ret) {
		HPRE_TST_PRT("failed to init alg, ret %d!\n", ret);
		return -1;
	}

	wd_free_list_accels(list);

	return ret;

}

static void uninit_hpre_global_config(__u32 op_type)
{
	if (op_type > HPRE_ALG_INVLD_TYPE && op_type < MAX_RSA_ASYNC_TYPE)
		wd_rsa_uninit();
	else if (op_type > MAX_RSA_ASYNC_TYPE && op_type < MAX_DH_TYPE)
		wd_dh_uninit();
	else
		wd_ecc_uninit();
}

static int init_opdata_param(struct wd_dh_req *req,
			     int key_size, enum dh_check_index step)
{
	unsigned char *ag_bin = NULL;

	memset(req, 0, sizeof(*req));
	if (step == DH_ALICE_PRIVKEY) {
		ag_bin = malloc(2 * key_size);
		if (!ag_bin)
			return -ENOMEM;
		memset(ag_bin, 0, 2 * key_size);
		req->pv = ag_bin;
	}

	req->x_p = malloc(2 * key_size);
	if (!req->x_p) {
		if (ag_bin)
			free(ag_bin);
		return -ENOMEM;
	}
	memset(req->x_p, 0, 2 * key_size);

	req->pri = malloc(2 * key_size);
	if (!req->pri) {
		if (ag_bin)
			free(ag_bin);
		free(req->x_p);
		return -ENOMEM;
	}
	memset(req->pri, 0, 2 * key_size);
	req->pri_bytes = 2 * key_size;

	return 0;
}


static EVP_PKEY *dh_new_from_params(BIGNUM *p, BIGNUM *g, BIGNUM *priv_key)
{
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	int selection = 0;

	bld = OSSL_PARAM_BLD_new();
	if (!bld)
		return NULL;

	if (p) {
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p);
		selection |= OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
	}
	if (g) {
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g);
		selection |= OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
	}
	if (priv_key) {
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_key);
		selection |= OSSL_KEYMGMT_SELECT_KEYPAIR;
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	OSSL_PARAM_BLD_free(bld);
	if (!params)
		return NULL;

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	if (!pctx) {
		OSSL_PARAM_free(params);
		return NULL;
	}

	EVP_PKEY_fromdata_init(pctx);
	EVP_PKEY_fromdata(pctx, &pkey, selection, params);
	EVP_PKEY_CTX_free(pctx);
	OSSL_PARAM_free(params);

	return pkey;
}
void hpre_dh_del_test_ctx(struct hpre_dh_test_ctx *test_ctx)
{
	if (!test_ctx)
		return;

	if (SW_GENERATE_KEY == test_ctx->op) {
		EVP_PKEY_free(test_ctx->priv);
	} else if (SW_COMPUTE_KEY == test_ctx->op) {
		struct hpre_dh_sw_opdata *req = test_ctx->req;

		free(req->except_pub_key);
		free(req->share_key);
		free(req);
		EVP_PKEY_free(test_ctx->priv);
	} else if (HW_GENERATE_KEY == test_ctx->op) {
		struct wd_dh_req *req = test_ctx->req;

		free(req->x_p);
		free(req->pri);
		free(req);
		free(test_ctx->cp_pub_key);
	} else if (HW_COMPUTE_KEY == test_ctx->op) {
		struct wd_dh_req *req = test_ctx->req;

		free(req->pv);
		free(req->x_p);
		free(req->pri);
		free(req);
		free(test_ctx->cp_share_key);
	} else {
		HPRE_TST_PRT("%s: no op %d\n", __func__, test_ctx->op);
	}

	free(test_ctx);
}

static struct hpre_dh_test_ctx *create_sw_gen_key_test_ctx(struct hpre_dh_test_ctx_setup setup)
{
	BIGNUM *p = NULL, *g = NULL, *x = NULL;
	struct hpre_dh_test_ctx *test_ctx;
	EVP_PKEY *dh = NULL;

	if (SW_GENERATE_KEY != setup.op_type) {
		HPRE_TST_PRT("%s: err op type %d\n", __func__, setup.op_type);
		return NULL;
	}

	test_ctx = malloc(sizeof(struct hpre_dh_test_ctx));
	if (!test_ctx)
		return NULL;

	if (setup.key_from) {
		p = BN_bin2bn(setup.p, setup.p_size, NULL);
		g = BN_bin2bn(setup.g, setup.g_size, NULL);
		x = BN_bin2bn(setup.x, setup.x_size, NULL);
		dh = dh_new_from_params(p, g, x);
		if (!dh) {
			free(test_ctx);
			BN_free(p);
			BN_free(g);
			BN_free(x);
			return NULL;
		}
	} else {
		EVP_PKEY_CTX *pctx;

		pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
		if (!pctx) {
			free(test_ctx);
			return NULL;
		}

		EVP_PKEY_paramgen_init(pctx);
		EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, setup.key_bits);
		EVP_PKEY_CTX_set_dh_paramgen_generator(pctx, setup.generator);
		if (EVP_PKEY_paramgen(pctx, &dh) <= 0) {
			HPRE_TST_PRT("EVP_PKEY_paramgen fail!\n");
			EVP_PKEY_CTX_free(pctx);
			free(test_ctx);
			return NULL;
		}
		EVP_PKEY_CTX_free(pctx);
	}

	test_ctx->op = SW_GENERATE_KEY;
	test_ctx->priv = dh;
	test_ctx->key_size = setup.key_bits >> 3;

	return test_ctx;
}

static struct hpre_dh_test_ctx *create_sw_compute_key_test_ctx(struct hpre_dh_test_ctx_setup setup)
{
	struct hpre_dh_sw_opdata *req;
	struct hpre_dh_test_ctx *test_ctx;
	EVP_PKEY *dh = NULL;

	if (!setup.except_pub_key ||
		!setup.except_pub_key_size ||
		setup.op_type !=SW_COMPUTE_KEY) {
		HPRE_TST_PRT("%s: parm err!\n", __func__);
		return NULL;
	}

	req = malloc(sizeof(struct hpre_dh_sw_opdata));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct hpre_dh_sw_opdata));

	test_ctx = malloc(sizeof(struct hpre_dh_test_ctx));
	if (!test_ctx) {
		free(req);
		return NULL;
	}
	memset(test_ctx, 0, sizeof(struct hpre_dh_test_ctx));

	req->share_key = malloc(setup.key_bits >> 3);
	if (!req->share_key) {
		free(req);
		free(test_ctx);
		return NULL;
	}

	if (setup.key_from) {
		BIGNUM *p = NULL, *g = NULL, *x = NULL;
		p = BN_bin2bn(setup.p, setup.p_size, NULL);
		g = BN_bin2bn(setup.g, setup.g_size, NULL);
		x = BN_bin2bn(setup.x, setup.x_size, NULL);
		dh = dh_new_from_params(p, g, x);
		BN_free(p);
		BN_free(g);
		BN_free(x);
		if (!dh) {
			free(req->share_key);
			free(req);
			free(test_ctx);
			return NULL;
		}

		req->except_pub_key = BN_bin2bn(setup.except_pub_key,
					setup.except_pub_key_size, NULL);

	} else {
		EVP_PKEY_CTX *pctx;
		EVP_PKEY *params = NULL;

		req->except_pub_key = BN_bin2bn(setup.except_pub_key,
			setup.except_pub_key_size, NULL);

		pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
		if (!pctx)
			goto exit_free;

		EVP_PKEY_paramgen_init(pctx);
		EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, setup.key_bits);
		EVP_PKEY_CTX_set_dh_paramgen_generator(pctx, setup.generator);
		if (EVP_PKEY_paramgen(pctx, &params) <= 0) {
			HPRE_TST_PRT("EVP_PKEY_paramgen fail!\n");
			EVP_PKEY_CTX_free(pctx);
			goto exit_free;
		}
		EVP_PKEY_CTX_free(pctx);

		{
		EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_pkey(NULL, params, NULL);
		EVP_PKEY_keygen_init(kctx);
		if (EVP_PKEY_keygen(kctx, &dh) <= 0) {
			HPRE_TST_PRT("EVP_PKEY_keygen fail!\n");
			EVP_PKEY_CTX_free(kctx);
			EVP_PKEY_free(params);
			goto exit_free;
		}
		EVP_PKEY_CTX_free(kctx);
		EVP_PKEY_free(params);
		}
	}

	test_ctx->op = SW_COMPUTE_KEY;
	test_ctx->priv = dh;
	test_ctx->req = req;
	test_ctx->key_size = setup.key_bits >> 3;

	return test_ctx;

exit_free:
	hpre_dh_del_test_ctx(test_ctx);

	return NULL;
}

static struct hpre_dh_test_ctx *create_hw_gen_key_test_ctx(struct hpre_dh_test_ctx_setup setup)
{
	BIGNUM *p = NULL, *g = NULL, *x = NULL;
	BIGNUM *pub_key = NULL;
	struct wd_dh_req *req;
	struct hpre_dh_test_ctx *test_ctx;
	struct wd_dtb ctx_g;
	int ret;
	u32 key_size = setup.key_bits >> 3;
	EVP_PKEY *dh = NULL;

	if (setup.op_type != HW_GENERATE_KEY) {
		HPRE_TST_PRT("%s: parm err!\n", __func__);
		return NULL;
	}

	req = malloc(sizeof(struct wd_dh_req));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct wd_dh_req));

	test_ctx = malloc(sizeof(struct hpre_dh_test_ctx));
	if (!test_ctx) {
		free(req);
		return NULL;
	}
	memset(test_ctx, 0, sizeof(struct hpre_dh_test_ctx));

	ctx_g.data = malloc(key_size);
	if (!ctx_g.data) {
		free(test_ctx);
		free(req);
		return NULL;
	}
	memset(ctx_g.data, 0, key_size);

	test_ctx->cp_pub_key = malloc(key_size);
	if (!test_ctx->cp_pub_key) {
		free(test_ctx);
		free(req);
		free(ctx_g.data);
		return NULL;
	}

	ret = init_opdata_param(req, key_size, DH_ALICE_PUBKEY);
	if (ret < 0) {
		HPRE_TST_PRT("init_opdata_param failed\n");
		free(test_ctx);
		free(req);
		free(ctx_g.data);
		return NULL;
	}

	if (setup.key_from) {
		if (!setup.x || !setup.x_size || !setup.p || !setup.pub_key ||
			!setup.p_size || !setup.g || !setup.g_size || !setup.pub_key_size) {
			HPRE_TST_PRT("%s: x/p/g parm err\n", __func__);
			goto exit_free;
		}

		memcpy(req->x_p, setup.x, setup.x_size);
		memcpy(req->x_p + key_size, setup.p, setup.p_size);
		memcpy(ctx_g.data, setup.g, setup.g_size);
		memcpy(test_ctx->cp_pub_key, setup.pub_key, setup.pub_key_size);
		req->pbytes = setup.p_size;
		req->xbytes = setup.x_size;
		ctx_g.dsize = setup.g_size;
		ctx_g.bsize = key_size;
		test_ctx->cp_pub_key_size = setup.pub_key_size;
	} else {
		EVP_PKEY_CTX *pctx;
		EVP_PKEY *params = NULL;

		pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
		if (!pctx)
			goto exit_free;

		EVP_PKEY_paramgen_init(pctx);
		EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, setup.key_bits);
		EVP_PKEY_CTX_set_dh_paramgen_generator(pctx, setup.generator);
		ret = EVP_PKEY_paramgen(pctx, &params);
		if (ret <= 0) {
			HPRE_TST_PRT("EVP_PKEY_paramgen failed\n");
			EVP_PKEY_CTX_free(pctx);
			goto exit_free;
		}
		EVP_PKEY_CTX_free(pctx);

		{
		EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_pkey(NULL, params, NULL);
		EVP_PKEY_keygen_init(kctx);
		ret = EVP_PKEY_keygen(kctx, &dh);
		if (ret <= 0) {
			HPRE_TST_PRT("EVP_PKEY_keygen failed\n");
			EVP_PKEY_CTX_free(kctx);
			EVP_PKEY_free(params);
			goto exit_free;
		}
		EVP_PKEY_CTX_free(kctx);
		EVP_PKEY_free(params);
		}

		EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_FFC_P, &p);
		EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_FFC_G, &g);
		EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_PUB_KEY, &pub_key);
		EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_PRIV_KEY, &x);

		req->pbytes = BN_bn2bin(p, req->x_p + key_size);
		req->xbytes = BN_bn2bin(x, req->x_p);
		ctx_g.dsize = BN_bn2bin(g, (unsigned char*)ctx_g.data);
		ctx_g.bsize = key_size;
		test_ctx->cp_pub_key_size = BN_bn2bin(pub_key, test_ctx->cp_pub_key);

		BN_free(p);
		BN_free(g);
		BN_free(pub_key);
		BN_free(x);
	}

#ifdef DEBUG
		print_data(ctx_g.data, ctx_g.dsize, "g");
		print_data(req->x_p, req->xbytes, "x");
		print_data(req->x_p + key_size, req->pbytes, "p");
		print_data(test_ctx->cp_pub_key, test_ctx->cp_pub_key_size, "cp_pub_key");
#endif

	req->op_type = WD_DH_PHASE1;
	test_ctx->req = req;
	test_ctx->op = setup.op_type;
	test_ctx->priv = (void *)setup.sess;
	test_ctx->key_size = key_size;

	ret = wd_dh_set_g((handle_t)test_ctx->priv, &ctx_g);
	if (ret) {
		HPRE_TST_PRT("wd_dh_set_g failed\n");
		goto exit_free;
	}


	EVP_PKEY_free(dh);
	free(ctx_g.data);

	return test_ctx;
exit_free:
	EVP_PKEY_free(dh);
	free(ctx_g.data);
	hpre_dh_del_test_ctx(test_ctx);

	return NULL;
}

static struct hpre_dh_test_ctx *create_hw_compute_key_test_ctx(struct hpre_dh_test_ctx_setup setup)
{
	BIGNUM *p = NULL, *g = NULL, *x = NULL;
	struct wd_dh_req *req;
	struct hpre_dh_test_ctx *test_ctx;
	int ret;
	u32 key_size = setup.key_bits >> 3;
	EVP_PKEY *dh = NULL;
	EVP_PKEY *b = NULL;

	if (setup.op_type !=HW_COMPUTE_KEY) {
		HPRE_TST_PRT("%s: parm err!\n", __func__);
		return NULL;
	}

	req = malloc(sizeof(struct wd_dh_req));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct wd_dh_req));

	test_ctx = malloc(sizeof(struct hpre_dh_test_ctx));
	if (!test_ctx) {
		free(req);
		return NULL;
	}
	memset(test_ctx, 0, sizeof(struct hpre_dh_test_ctx));

	test_ctx->cp_share_key = malloc(key_size);
	if (!test_ctx->cp_share_key) {
		free(test_ctx);
		free(req);
		return NULL;
	}

	ret = init_opdata_param(req, key_size, DH_ALICE_PRIVKEY);
	if (ret < 0) {
		HPRE_TST_PRT("init_opdata_param failed\n");
		free(test_ctx);
		free(req);
		return NULL;
	}

	if (setup.key_from) {
		memcpy(req->x_p, setup.x, setup.x_size);
		memcpy(req->x_p + key_size, setup.p, setup.p_size);
		memcpy(req->pv, setup.except_pub_key, setup.except_pub_key_size);
		memcpy(test_ctx->cp_share_key, setup.share_key, setup.share_key_size);
		req->pbytes = setup.p_size;
		req->xbytes = setup.x_size;
		req->pvbytes = setup.except_pub_key_size;
		test_ctx->cp_share_key_size = setup.share_key_size;
	} else {
		BIGNUM *bpub_key = NULL;
		EVP_PKEY_CTX *pctx;
		EVP_PKEY *params = NULL;

		pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
		if (!pctx)
			goto exit_free;

		EVP_PKEY_paramgen_init(pctx);
		EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, setup.key_bits);
		EVP_PKEY_CTX_set_dh_paramgen_generator(pctx, setup.generator);
		ret = EVP_PKEY_paramgen(pctx, &params);
		if (ret <= 0) {
			HPRE_TST_PRT("EVP_PKEY_paramgen fail!\n");
			EVP_PKEY_CTX_free(pctx);
			goto exit_free;
		}
		EVP_PKEY_CTX_free(pctx);

		{
		EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_pkey(NULL, params, NULL);
		EVP_PKEY_keygen_init(kctx);
		ret = EVP_PKEY_keygen(kctx, &dh);
		if (ret <= 0) {
			HPRE_TST_PRT("Alice EVP_PKEY_keygen fail!\n");
			EVP_PKEY_CTX_free(kctx);
			EVP_PKEY_free(params);
			goto exit_free;
		}
		EVP_PKEY_CTX_free(kctx);
		EVP_PKEY_free(params);
		}

		EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_FFC_P, &p);
		EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_FFC_G, &g);
		EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_PRIV_KEY, &x);

		b = dh_new_from_params(p, g, NULL);
		if (!b) {
			ret = -1;
			goto exit_free;
		}
		{
		EVP_PKEY_CTX *bkctx = EVP_PKEY_CTX_new_from_pkey(NULL, b, NULL);
		EVP_PKEY_keygen_init(bkctx);
		EVP_PKEY_free(b);
		ret = EVP_PKEY_keygen(bkctx, &b);
		if (ret <= 0) {
			HPRE_TST_PRT("Bob EVP_PKEY_keygen fail!\n");
			EVP_PKEY_CTX_free(bkctx);
			ret = -1;
			goto exit_free;
		}
		EVP_PKEY_CTX_free(bkctx);
		}

		EVP_PKEY_get_bn_param(b, OSSL_PKEY_PARAM_PUB_KEY, &bpub_key);

		{
		EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(dh, NULL);
		EVP_PKEY_derive_init(dctx);
		EVP_PKEY_derive_set_peer(dctx, b);
		size_t derive_sz = key_size;
		EVP_PKEY_derive(dctx, test_ctx->cp_share_key, &derive_sz);
		test_ctx->cp_share_key_size = derive_sz;
		EVP_PKEY_CTX_free(dctx);
		}

		req->pbytes = BN_bn2bin(p, req->x_p + key_size);
		req->xbytes = BN_bn2bin(x, req->x_p);
		req->pvbytes = BN_bn2bin(bpub_key, req->pv);

		BN_free(p);
		BN_free(g);
		BN_free(x);
		BN_free(bpub_key);
	}

	req->op_type = WD_DH_PHASE2;
	test_ctx->priv = (void *)setup.sess; //init sess
	test_ctx->req = req;
	test_ctx->op = setup.op_type;
	test_ctx->key_size = key_size;

#ifdef DEBUG
	print_data(req->pv, req->pvbytes, "pv");
	print_data(req->x_p, req->xbytes, "x");
	print_data(req->x_p + key_size, req->pbytes, "p");
	print_data(test_ctx->cp_share_key, test_ctx->cp_share_key_size, "cp_share_key");
#endif

	EVP_PKEY_free(dh);
	if (b)
		EVP_PKEY_free(b);

	return test_ctx;
exit_free:
	EVP_PKEY_free(dh);
	if (b)
		EVP_PKEY_free(b);
	hpre_dh_del_test_ctx(test_ctx);

	return NULL;
}


struct hpre_dh_test_ctx *hpre_dh_create_test_ctx(struct hpre_dh_test_ctx_setup setup)
{
	struct hpre_dh_test_ctx *test_ctx = NULL;

	switch (setup.op_type) {
		case SW_GENERATE_KEY:
		{
			test_ctx = create_sw_gen_key_test_ctx(setup);
		}
		break;
		case HW_GENERATE_KEY:
		{
			test_ctx = create_hw_gen_key_test_ctx(setup);
		}
		break;
		case SW_COMPUTE_KEY:
		{
			test_ctx = create_sw_compute_key_test_ctx(setup);
		}
		break;
		case HW_COMPUTE_KEY:
		{
			test_ctx = create_hw_compute_key_test_ctx(setup);
		}
		break;
		default:
		break;
	}

	return test_ctx;
}

int dh_generate_key(void *test_ctx, void *tag)
{
	struct hpre_dh_test_ctx *t_c = test_ctx;
	int ret = 0;

	if (t_c->op == SW_GENERATE_KEY) {
		EVP_PKEY *dh = t_c->priv;
		EVP_PKEY_CTX *kctx;

		kctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh, NULL);
		if (!kctx)
			return -1;

		EVP_PKEY_keygen_init(kctx);
		EVP_PKEY_free(dh);
		if (EVP_PKEY_keygen(kctx, &dh) <= 0) {
			HPRE_TST_PRT("EVP_PKEY_keygen fail!\n");
			EVP_PKEY_CTX_free(kctx);
			return -1;
		}
		EVP_PKEY_CTX_free(kctx);
		t_c->priv = dh;

	} else {
		struct wd_dh_req *req = t_c->req;
		handle_t sess = (handle_t)t_c->priv;
try_again:
		if (tag)
			ret = wd_do_dh_async(sess, req);
		else
			ret = wd_do_dh_sync(sess, req);
		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_again;
		} else if (ret) {
			HPRE_TST_PRT("wd_do_dh fail!\n");
			return -1;
		}
	}

	return 0;
}

int dh_compute_key(void *test_ctx, void *tag)
{
	struct hpre_dh_test_ctx *t_c = test_ctx;
	int ret = 0;

	if (t_c->op == SW_COMPUTE_KEY) {
		struct hpre_dh_sw_opdata *req = t_c->req;
		EVP_PKEY *dh = t_c->priv;
		BIGNUM *p = NULL, *g = NULL;
		EVP_PKEY *peer = NULL;
		EVP_PKEY_CTX *dctx;
		OSSL_PARAM_BLD *bld;
		OSSL_PARAM *params;
		int selection = 0;
		size_t derive_sz;

		EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_FFC_P, &p);
		EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_FFC_G, &g);

		bld = OSSL_PARAM_BLD_new();
		if (!bld) {
			BN_free(p);
			BN_free(g);
			return -1;
		}
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p);
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g);
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, req->except_pub_key);
		selection = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS |
			    OSSL_KEYMGMT_SELECT_KEYPAIR;
		params = OSSL_PARAM_BLD_to_param(bld);
		OSSL_PARAM_BLD_free(bld);
		if (!params) {
			BN_free(p);
			BN_free(g);
			return -1;
		}

		{
		EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
		if (pctx) {
			EVP_PKEY_fromdata_init(pctx);
			EVP_PKEY_fromdata(pctx, &peer, selection, params);
			EVP_PKEY_CTX_free(pctx);
		}
		}
		OSSL_PARAM_free(params);
		BN_free(p);
		BN_free(g);
		if (!peer)
			return -1;

		dctx = EVP_PKEY_CTX_new(dh, NULL);
		if (!dctx) {
			EVP_PKEY_free(peer);
			return -1;
		}
		EVP_PKEY_derive_init(dctx);
		EVP_PKEY_derive_set_peer(dctx, peer);
		derive_sz = t_c->key_size;
		ret = EVP_PKEY_derive(dctx, req->share_key, &derive_sz);
		EVP_PKEY_CTX_free(dctx);
		EVP_PKEY_free(peer);
		if (ret <= 0) {
			HPRE_TST_PRT("EVP_PKEY_derive fail!\n");
			return -1;
		}
		req->share_key_size = derive_sz;
	} else {
		struct wd_dh_req *req = t_c->req;
		handle_t sess = (uintptr_t)t_c->priv;
try_again:
		if (tag)
			ret = wd_do_dh_async(sess, req);
		else
			ret = wd_do_dh_sync(sess, req);
		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_again;
		} else if (ret) {
			HPRE_TST_PRT("wd_do_dh fail!\n");
			return -1;
		}
#ifdef DEBUG
		//print_data(req->pri, req->pri_bytes,"hpre share key");
#endif
	}

	return 0;
}

static bool is_exit(struct test_hpre_pthread_dt *pdata)
{
	struct timeval cur_tval;
	float time_used;

	gettimeofday(&cur_tval, NULL);
	time_used = (float)((cur_tval.tv_sec -pdata->start_tval.tv_sec) * 1000000 +
			cur_tval.tv_usec - pdata->start_tval.tv_usec);

	if (g_config.seconds)
		return time_used >= g_config.seconds * 1000000;
	else if (g_config.times)
		return pdata->send_task_num >= g_config.times;

	return false;
}

static int dh_result_check(struct hpre_dh_test_ctx *test_ctx)
{
	struct wd_dh_req *req = test_ctx->req;
	unsigned char *cp_key;
	u32 cp_size;

	if (test_ctx->op == HW_GENERATE_KEY) {
		cp_key = test_ctx->cp_pub_key;
		cp_size = test_ctx->cp_pub_key_size;

	} else {
		cp_key = test_ctx->cp_share_key;
		cp_size = test_ctx->cp_share_key_size;
	}

	if (req->pri_bytes != cp_size || memcmp(cp_key, req->pri, cp_size)) {
		HPRE_TST_PRT("dh op %d mismatch!\n", test_ctx->op);

#ifdef DEBUG
	print_data(req->pri, req->pri_bytes, "hpre out");
	print_data(cp_key, cp_size, "openssl out");
#endif

		return -1;
	}

	return 0;

}

static bool is_allow_print(int cnt, enum alg_op_type opType, int thread_num)
{
	int intval_index = 0;
	unsigned int log_intval_adjust = 0;
	int log_intval[LOG_INTVL_NUM] = {0x1, 0xff, 0x3ff, 0x7ff, 0xfff, 0x1fff};

	if (!g_config.with_log || g_config.perf_test)
		return false;

	if (g_config.soft_test)
		return true;

	switch (opType) {
		case RSA_ASYNC_GEN:
		case RSA_ASYNC_EN:
		case RSA_ASYNC_DE:
		case DH_ASYNC_COMPUTE:
		case DH_ASYNC_GEN:
		case RSA_KEY_GEN:
		{
			intval_index = 0x04;
		}
		break;
		case ECDH_ASYNC_COMPUTE:
		case ECDH_ASYNC_GEN:
		case ECDSA_ASYNC_SIGN:
		case ECDSA_ASYNC_VERF:
		case ECDH_COMPUTE:
		case ECDH_GEN:
		{
			intval_index = 0x01;
		}
		break;
		case DH_COMPUTE:
		case DH_GEN:
		{
			intval_index = 0x00;
		}
		break;
		default:
		{
			intval_index = 0x01;
		}
		break;
	}

	if (!thread_num)
		return false;
	log_intval_adjust = log_intval[intval_index] * ((thread_num - 1) / 16 + 1);

	if (!(cnt % log_intval_adjust))
		return true;
	else
		return false;
}

static void _dh_perf_cb(void *req_t)
{
	struct wd_dh_req *req = req_t;
	struct dh_user_tag_info* pTag = (struct dh_user_tag_info*)req->cb_param;
	struct test_hpre_pthread_dt *thread_data = pTag->thread_data;

	thread_data->recv_task_num++;
	hpre_dh_del_test_ctx(pTag->test_ctx);
	free(pTag);
}

static void _dh_cb(void *req_t)
{
	struct wd_dh_req *req = req_t;
	struct dh_user_tag_info* pSwData = (struct dh_user_tag_info*)req->cb_param;
	struct timeval start_tval, end_tval;
	int pid, threadId;
	float time, speed;
	int ret;
	static int failTimes = 0;
	struct hpre_dh_test_ctx *test_ctx = pSwData->test_ctx;
	struct test_hpre_pthread_dt *thread_data = pSwData->thread_data;

	start_tval = thread_data->start_tval;
	pid = pSwData->pid;
	threadId = pSwData->thread_id;
	thread_data->recv_task_num++;

	if (req->status != WD_SUCCESS) {
		HPRE_TST_PRT("Proc-%d, %d-TD dh %dtimes fail!, status 0x%02x\n",
				 pid, threadId, thread_data->send_task_num, req->status);
		goto err;
	}

	if (g_config.check) {
		((struct wd_dh_req *)test_ctx->req)->pri_bytes = req->pri_bytes;
		ret = dh_result_check(test_ctx);
		if (ret) {
			failTimes++;
			HPRE_TST_PRT("TD-%d:dh %d result mismatching!\n",
				threadId, test_ctx->op);
		}
	}

	gettimeofday(&end_tval, NULL);
	if (is_allow_print(thread_data->send_task_num, DH_ASYNC_GEN, 1)) {
		time = (end_tval.tv_sec - start_tval.tv_sec) * 1000000 +
					(end_tval.tv_usec - start_tval.tv_usec);
		speed = 1 / (time / thread_data->send_task_num) * 1000 * 1000;
		HPRE_TST_PRT("Proc-%d, %d-TD dh %dtimes,%f us, %0.3fps, fail %dtimes(all TD)\n",
				 pid, threadId, thread_data->send_task_num, time, speed, failTimes);
	}

err:
	if (is_allow_print(thread_data->send_task_num, DH_ASYNC_GEN, 1))
		HPRE_TST_PRT("thread %d do DH %dth time success!\n", threadId, thread_data->send_task_num);
	hpre_dh_del_test_ctx(test_ctx);
	if (pSwData)
		free(pSwData);
}


int dh_init_test_ctx_setup(struct hpre_dh_test_ctx_setup *setup)
{
	__u32 key_bits = g_config.key_bits;

	if (!setup)
		return -1;

	if (!strcmp(g_config.alg_mode, "g2"))
		setup->generator = DH_GENERATOR_2;
	else
		setup->generator = DH_GENERATOR_5;

	if (g_config.perf_test)
		setup->key_from = 1; //0 - Openssl  1 - Designed
	else
		setup->key_from = 0; //0 - Openssl  1 - Designed

	setup->key_bits = g_config.key_bits;

	if (key_bits == 768) {
		setup->x = dh_xa_768;
		setup->p = dh_p_768;
		setup->except_pub_key = dh_except_b_pubkey_768;
		setup->pub_key = dh_except_a_pubkey_768;
		setup->share_key = dh_share_key_768;
		setup->x_size = sizeof(dh_xa_768);
		setup->p_size = sizeof(dh_p_768);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_768);
		setup->pub_key_size = sizeof(dh_except_a_pubkey_768);
		setup->share_key_size = sizeof(dh_share_key_768);
	} else if (key_bits == 1024) {
		setup->x = dh_xa_1024;
		setup->p = dh_p_1024;
		setup->except_pub_key = dh_except_b_pubkey_1024;
		setup->pub_key = dh_except_a_pubkey_1024;
		setup->share_key = dh_share_key_1024;
		setup->x_size = sizeof(dh_xa_1024);
		setup->p_size = sizeof(dh_p_1024);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_1024);
		setup->pub_key_size = sizeof(dh_except_a_pubkey_1024);
		setup->share_key_size = sizeof(dh_share_key_1024);
	} else if (key_bits == 1536) {
		setup->x = dh_xa_1536;
		setup->p = dh_p_1536;
		setup->except_pub_key = dh_except_b_pubkey_1536;
		setup->pub_key = dh_except_a_pubkey_1536;
		setup->share_key = dh_share_key_1536;
		setup->x_size = sizeof(dh_xa_1536);
		setup->p_size = sizeof(dh_p_1536);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_1536);
		setup->pub_key_size = sizeof(dh_except_a_pubkey_1536);
		setup->share_key_size = sizeof(dh_share_key_1536);
	} else if (key_bits == 2048) {
		setup->x = dh_xa_2048;
		setup->p = dh_p_2048;
		setup->except_pub_key = dh_except_b_pubkey_2048;
		setup->pub_key = dh_except_a_pubkey_2048;
		setup->share_key = dh_share_key_2048;
		setup->x_size = sizeof(dh_xa_2048);
		setup->p_size = sizeof(dh_p_2048);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_2048);
		setup->pub_key_size = sizeof(dh_except_a_pubkey_2048);
		setup->share_key_size = sizeof(dh_share_key_2048);
	} else if (key_bits == 3072) {
		setup->x = dh_xa_3072;
		setup->p = dh_p_3072;
		setup->except_pub_key = dh_except_b_pubkey_3072;
		setup->pub_key = dh_except_a_pubkey_3072;
		setup->share_key = dh_share_key_3072;
		setup->x_size = sizeof(dh_xa_3072);
		setup->p_size = sizeof(dh_p_3072);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_3072);
		setup->pub_key_size = sizeof(dh_except_a_pubkey_3072);
		setup->share_key_size = sizeof(dh_share_key_3072);
	} else if (key_bits == 4096) {
		setup->x = dh_xa_4096;
		setup->p = dh_p_4096;
		setup->except_pub_key = dh_except_b_pubkey_4096;
		setup->pub_key = dh_except_a_pubkey_4096;
		setup->share_key = dh_share_key_4096;
		setup->x_size = sizeof(dh_xa_4096);
		setup->p_size = sizeof(dh_p_4096);
		setup->except_pub_key_size = sizeof(dh_except_b_pubkey_4096);
		setup->pub_key_size = sizeof(dh_except_a_pubkey_4096);
		setup->share_key_size = sizeof(dh_share_key_4096);
	} else {
		HPRE_TST_PRT("not find this keybits %d\n", key_bits);
		return -1;
	}

	if (!strcmp(g_config.alg_mode, "g2")) {
		setup->g = dh_g_2;
	} else {
		setup->g = dh_g_5;
	}
	setup->g_size = 1;

	return 0;
}

static void *_hpre_dh_sys_test_thread(void *data)
{
	struct test_hpre_pthread_dt *pdata = data;
	struct dh_user_tag_info *pTag = NULL;
	struct hpre_dh_test_ctx *test_ctx;
	struct hpre_dh_test_ctx_setup setup;
	struct timeval cur_tval;
	enum alg_op_type opType;
	float time_used, speed = 0.0;
	int thread_num;
	cpu_set_t mask;
	int pid = getpid();
	int thread_id = (int)syscall(__NR_gettid);
	int ret, cpuid;
	handle_t sess = 0llu;
	struct wd_dh_sess_setup dh_setup;
	struct wd_dh_req *req;

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	opType = pdata->op_type;
	thread_num = pdata->thread_num;

	if (g_config.perf_test && (!g_config.times && !g_config.seconds)) {
		HPRE_TST_PRT("g_config.times or  g_config.seconds err\n");
		return NULL;
	}

	CPU_SET(cpuid, &mask);
	if (cpuid) {
		ret = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);
		if (ret < 0) {
			HPRE_TST_PRT("Proc-%d, thrd-%d:set affinity fail!\n",
						 pid, thread_id);
			return NULL;
		}
		HPRE_TST_PRT("Proc-%d, thrd-%d bind to cpu-%d!\n",
					 pid, thread_id, cpuid);
	}

	if (!g_config.soft_test) {
		memset(&dh_setup, 0, sizeof(dh_setup));
		dh_setup.key_bits = g_config.key_bits;
		if (!strcmp(g_config.alg_mode, "g2"))
			dh_setup.is_g2 = true;
		else
			dh_setup.is_g2 = false;

		sess = wd_dh_alloc_sess(&dh_setup);
		if (!sess) {
			HPRE_TST_PRT("wd_dh_alloc_ctx failed\n");
			return NULL;
		}
	}

	if (dh_init_test_ctx_setup(&setup)) {
		wd_dh_free_sess(sess);
		return NULL;
	}

	setup.sess = sess;

	if (opType == DH_ASYNC_GEN || opType == DH_GEN)
		setup.op_type = (g_config.soft_test) ? SW_GENERATE_KEY: HW_GENERATE_KEY;
	else
		setup.op_type = (g_config.soft_test) ? SW_COMPUTE_KEY: HW_COMPUTE_KEY;

new_test_again:
	test_ctx = hpre_dh_create_test_ctx(setup);
	if (!test_ctx) {
		HPRE_TST_PRT("hpre_dh_create_test_ctx failed\n");
		return NULL;
	}

	req = test_ctx->req;
	do {
		if (opType == DH_ASYNC_GEN ||
			opType == DH_ASYNC_COMPUTE) {

			pTag = malloc(sizeof(struct dh_user_tag_info));
			if (!pTag) {
				HPRE_TST_PRT("malloc pTag fail!\n");
				goto fail_release;
			}

			pTag->test_ctx = test_ctx;
			pTag->thread_data = pdata;
			pTag->pid = pid;
			pTag->thread_id = thread_id;
			if (g_config.perf_test)
				req->cb = _dh_perf_cb;
			else
				req->cb = _dh_cb;
			req->cb_param = pTag;
		}

		if (opType == DH_ASYNC_GEN || opType == DH_GEN) {
			if (dh_generate_key(test_ctx, pTag)) {
				goto fail_release;
			}
		} else {
			if (dh_compute_key(test_ctx, pTag)) {
				goto fail_release;
			}
		}

		pdata->send_task_num++;
		if (opType == DH_GEN ||opType == DH_COMPUTE) {
			if (!g_config.perf_test && !g_config.soft_test) {
				if (dh_result_check(test_ctx))
					goto fail_release;

				if (is_allow_print(pdata->send_task_num, opType, thread_num)) {
					HPRE_TST_PRT("Proc-%d, %d-TD %s succ!\n",
						getpid(), (int)syscall(__NR_gettid), g_config.op);
				}

				hpre_dh_del_test_ctx(test_ctx);
				if (is_exit(pdata))
					return 0;
				goto new_test_again;
			}
		} else {
			if (is_exit(pdata))
				break;
			goto new_test_again;
		}

	}while(!is_exit(pdata));

	if (opType == DH_GEN || opType == DH_COMPUTE)
		pdata->recv_task_num = pdata->send_task_num;

	if (g_config.perf_test) {
		gettimeofday(&cur_tval, NULL);
		time_used = (float)((cur_tval.tv_sec -pdata->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - pdata->start_tval.tv_usec);

		if (g_config.seconds){
			speed = pdata->recv_task_num / time_used * 1000000;
		} else if (g_config.times) {
			speed = pdata->recv_task_num * 1.0 * 1000 * 1000 / time_used;
		}
		HPRE_TST_PRT("<< Proc-%d, %d-TD: run %s %s mode %u key_bits at %0.3f ops!\n",
			pid, thread_id, g_config.op, g_config.alg_mode, g_config.key_bits, speed);
		pdata->perf = speed;
	}

	/* wait for recv finish */
	while (pdata->send_task_num != pdata->recv_task_num) {
		usleep(1000 * 1000);
		if (g_config.with_log)
			HPRE_TST_PRT("<< Proc-%d, %d-TD: total send %u: recv %u, wait recv finish...!\n",
				pid, thread_id, pdata->send_task_num, pdata->recv_task_num);
	}

fail_release:
	if (opType == DH_ASYNC_GEN ||
		opType == DH_ASYNC_COMPUTE) {
		return NULL;
	}
	if (test_ctx->op == HW_COMPUTE_KEY || test_ctx->op == HW_GENERATE_KEY)
		wd_dh_free_sess((uintptr_t)test_ctx->priv);

	if (opType == DH_GEN || opType == DH_COMPUTE)
		hpre_dh_del_test_ctx(test_ctx);

	return NULL;
}


static void ecc_del_test_ctx(struct ecc_test_ctx *test_ctx)
{
	if (!test_ctx)
		return;

	if (ECDH_SW_GENERATE == test_ctx->setup.op_type) {
		if (test_ctx->is_x25519_x448 == 1) {

		} else {
			EVP_PKEY_free(test_ctx->setup.openssl_handle);
		}
	} else if (ECDH_SW_COMPUTE == test_ctx->setup.op_type) {
		struct ecdh_sw_opdata *opdata = test_ctx->req;

		if (test_ctx->is_x25519_x448 == 1) {

		} else {
			free(opdata->share_key);
			free(opdata);
			EVP_PKEY_free(test_ctx->setup.openssl_handle);
		}
	} else if (ECDH_HW_GENERATE == test_ctx->setup.op_type) {
		struct wd_ecc_req *req = test_ctx->req;

		wd_ecc_del_out(test_ctx->setup.sess, req->dst);
		free(req);
		free(test_ctx->cp_pub_key);
	} else if (ECDH_HW_COMPUTE == test_ctx->setup.op_type) {
		struct wd_ecc_req *req = test_ctx->req;

		wd_ecc_del_out(test_ctx->setup.sess, req->dst);
		wd_ecc_del_in(test_ctx->setup.sess, req->src);
		free(req);
		free(test_ctx->cp_share_key);
	} else if (ECC_SW_SIGN == test_ctx->setup.op_type) {
		struct ecdh_sw_opdata *opdata = test_ctx->req;

		free(opdata->sign);
		BN_free(opdata->except_kinv);
		free(opdata);
		EVP_PKEY_free(test_ctx->priv);
	} else if (ECC_SW_VERF == test_ctx->setup.op_type) {
		struct ecdh_sw_opdata *opdata = test_ctx->req;

		free(opdata);
		EVP_PKEY_free(test_ctx->priv);
	} else if (ECC_HW_SIGN == test_ctx->setup.op_type) {
		struct wd_ecc_req *req = test_ctx->req;

		if (test_ctx->priv1)
			EVP_PKEY_free(test_ctx->priv1);

		wd_ecc_del_out((handle_t)test_ctx->priv, req->dst);
		wd_ecc_del_in((handle_t)test_ctx->priv, req->src);
		free(req);
	} else if (ECC_HW_VERF == test_ctx->setup.op_type) {
		struct wd_ecc_req *req = test_ctx->req;

		wd_ecc_del_in((handle_t)test_ctx->priv, req->src);
		free(req);
	} else if (SM2_SW_SIGN == test_ctx->setup.op_type) {
	} else if (SM2_HW_SIGN == test_ctx->setup.op_type ||
		SM2_HW_VERF == test_ctx->setup.op_type ||
		SM2_HW_ENC == test_ctx->setup.op_type ||
		SM2_HW_DEC == test_ctx->setup.op_type ||
		SM2_HW_KG == test_ctx->setup.op_type) {
		struct wd_ecc_req *req = test_ctx->req;

		if (req->src)
			wd_ecc_del_in(test_ctx->setup.sess, req->src);
		if (req->dst)
			wd_ecc_del_out(test_ctx->setup.sess, req->dst);
		free(req);
	} else {
		HPRE_TST_PRT("%s: no op %d\n", __func__, test_ctx->setup.op_type);
	}

	free(test_ctx);
}

static int get_ecc_nid(const char *name, __u32 *nid, __u32 *curve_id)
{
	int i;

	for (i = 0; i < sizeof(ecc_curve_tbls) / sizeof(ecc_curve_tbls[0]); i++) {

		if (!strcmp(name, ecc_curve_tbls[i].name)) {
			*nid = ecc_curve_tbls[i].nid;
			*curve_id = ecc_curve_tbls[i].curve_id;
			return 0;
		}
	}

	return -1;
}

static int hpre_get_rand(char *out, size_t out_len, void *usr)
{
	int ret;

	if (!out) {
		return -1;
	}

	ret = RAND_priv_bytes((void *)out, out_len);
	if (ret != 1) {
		HPRE_TST_PRT("RAND_priv_bytes fail = %d\n", ret);
		return -1;
	}

	return 0;
}

static int get_hash_bytes(void)
{
	__u32 val = 0;

	switch (g_config.hash_type) {
	case HASH_MD4:
	case HASH_MD5:
		val = BITS_TO_BYTES(128);
		break;
	case HASH_SHA1:
		val = BITS_TO_BYTES(160);
		break;
	case HASH_SHA224:
		val = BITS_TO_BYTES(224);
		break;
	case HASH_SHA256:
	case HASH_SM3:
		val = BITS_TO_BYTES(256);
		break;
	case HASH_SHA384:
		val = BITS_TO_BYTES(384);
		break;
	case HASH_SHA512:
		val = BITS_TO_BYTES(512);
		break;
	default:
		break;
	}

	return val;
}

static const EVP_MD *get_digest_handle(void)
{
	const EVP_MD *digest;

	switch (g_config.hash_type) {
	case HASH_MD4:
		digest = EVP_md4();
		break;
	case HASH_MD5:
		digest = EVP_md5();
		break;
	case HASH_SHA1:
		digest = EVP_sha1();
		break;
	case HASH_SHA224:
		digest = EVP_sha224();
		break;
	case HASH_SHA256:
		digest = EVP_sha256();
		break;
	case HASH_SM3:
		digest = EVP_sm3();
		break;
	case HASH_SHA384:
		digest = EVP_sha384();
		break;
	case HASH_SHA512:
		digest = EVP_sha512();
		break;
	default:
		digest = EVP_sm3();
		break;
	}

	return digest;
}

static int hpre_compute_hash(const char *in, size_t in_len,
		       char *out, size_t out_len, void *usr)
{
	const EVP_MD *digest;
	EVP_MD_CTX *hash = EVP_MD_CTX_new();
	int ret = 0;

	digest = get_digest_handle();
	if (EVP_DigestInit(hash, digest) == 0 ||
		EVP_DigestUpdate(hash, in, in_len) == 0 ||
		EVP_DigestFinal(hash, (void *)out, NULL) == 0) {
			HPRE_TST_PRT("compute hash failed\n");
			ret = -1;
		}

	EVP_MD_CTX_free(hash);

	return ret;
}

static EVP_PKEY *create_evp_pkey(__u32 nid, struct wd_dtb *pubkey, struct wd_dtb *prikey)
{
	EVP_PKEY *pkey = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	int ret;

	bld = OSSL_PARAM_BLD_new();
	if (!bld)
		return NULL;

	OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, OBJ_nid2sn(nid), 0);

	/* set pubkey */
	if (pubkey && pubkey->data && pubkey->dsize) {
		OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pubkey->data, pubkey->dsize);
	}

	/* set prikey */
	if (prikey && prikey->data && prikey->dsize) {
		OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY, prikey->data, prikey->dsize);
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (!params) {
		printf("OSSL_PARAM_BLD_to_param err!\n");
		OSSL_PARAM_BLD_free(bld);
		return NULL;
	}
	OSSL_PARAM_BLD_free(bld);

	pkey = EVP_PKEY_fromdata(NULL, NULL, OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, params);
	if (!pkey) {
		printf("EVP_PKEY_fromdata err!\n");
		OSSL_PARAM_free(params);
		return NULL;
	}
	OSSL_PARAM_free(params);

	return pkey;
}

static EVP_MD_CTX *create_evp_md_ctx(__u32 nid, EVP_PKEY *pkey)
{
	EVP_MD_CTX *md_ctx;
	EVP_PKEY_CTX *pctx;

	pctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!pctx) {
		printf("EVP_PKEY_CTX_new failed\n");
		return NULL;
	}

	md_ctx = EVP_MD_CTX_new();
	if (!md_ctx) {
		printf("EVP_MD_CTX_new failed\n");
		EVP_PKEY_CTX_free(pctx);
		return NULL;
	}

	EVP_MD_CTX_set_pkey_ctx(md_ctx, pctx);

	return md_ctx;
}

static void del_evp_md_ctx(EVP_MD_CTX *md_ctx)
{
	EVP_PKEY_CTX *pctx = EVP_MD_CTX_pkey_ctx(md_ctx);
	EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(pctx);

	/* pkey from get0 must NOT be freed separately */
	(void)pkey;
	EVP_PKEY_CTX_free(pctx);
	EVP_MD_CTX_free(md_ctx);
}

static void *ecc_create_openssl_handle(struct wd_dtb *prk, struct wd_dtb *pbk)
{
	EVP_MD_CTX *md_ctx;
	EVP_PKEY *pkey;

	pkey = create_evp_pkey(EVP_PKEY_SM2, pbk, prk);
	if (!pkey)
		return NULL;

	md_ctx = create_evp_md_ctx(EVP_PKEY_SM2, pkey);
	if (!md_ctx)
		goto del_pkey;

	return md_ctx;

del_pkey:
	EVP_PKEY_free(pkey);

	return NULL;
}

static void ecc_del_openssl_handle(void *handle)
{
	EVP_MD_CTX *md_ctx = handle;

	del_evp_md_ctx(md_ctx);
}

static int set_sess_key(handle_t sess, struct wd_dtb *prk, struct wd_ecc_point *pbk)
{
	struct wd_ecc_key *ecc_key;
	int ret;

	ecc_key = wd_ecc_get_key(sess);
	if (prk) {
		ret = wd_ecc_set_prikey(ecc_key, prk);
		if (ret) {
			HPRE_TST_PRT("%s: set prikey err\n", __func__);
			return -1;
		}
	}

	if (pbk) {
		ret = wd_ecc_set_pubkey(ecc_key, pbk);
		if (ret) {
			HPRE_TST_PRT("%s: set pubkey err\n", __func__);
			return -1;
		}
	}

	return 0;
}

static struct ecc_test_ctx *ecdh_create_sw_gen_test_ctx(struct ecc_test_ctx_setup setup, u32 optype)
{
	struct ecc_test_ctx *test_ctx;
	EVP_PKEY *key = NULL;
	EVP_PKEY_CTX *kctx;
	int ret;

	if (ECDH_SW_GENERATE != setup.op_type) {
		HPRE_TST_PRT("%s: err op type %d\n", __func__, setup.op_type);
		return NULL;
	}

	kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (!kctx) {
		printf("EVP_PKEY_CTX_new_from_name err!\n");
		return NULL;
	}

	ret = EVP_PKEY_keygen_init(kctx);
	if (ret != 1) {
		printf("EVP_PKEY_keygen_init err!\n");
		EVP_PKEY_CTX_free(kctx);
		return NULL;
	}

	ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, setup.nid);
	if (ret != 1) {
		printf("EVP_PKEY_CTX_set_ec_paramgen_curve_nid err!\n");
		EVP_PKEY_CTX_free(kctx);
		return NULL;
	}

	ret = EVP_PKEY_keygen(kctx, &key);
	EVP_PKEY_CTX_free(kctx);
	if (ret != 1) {
		printf("EVP_PKEY_keygen err!\n");
		return NULL;
	}

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		printf("malloc failed.\n");
			EVP_PKEY_free(key);
		return NULL;
	}

	if (setup.key_from) {
		EVP_PKEY *old_key = key;
		OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
		OSSL_PARAM *params;
		BIGNUM *privKey;

		if (!bld) {
			printf("OSSL_PARAM_BLD_new err!\n");
			EVP_PKEY_free(key);
			free(test_ctx);
			return NULL;
		}

		OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, OBJ_nid2sn(setup.nid), 0);
		privKey = BN_bin2bn(setup.priv_key, setup.priv_key_size, NULL);
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, privKey);
		params = OSSL_PARAM_BLD_to_param(bld);
		OSSL_PARAM_BLD_free(bld);

		if (!params) {
			printf("OSSL_PARAM_BLD_to_param err!\n");
			BN_free(privKey);
			EVP_PKEY_free(key);
			free(test_ctx);
			return NULL;
		}

		key = EVP_PKEY_fromdata(NULL, NULL, OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, params);
		OSSL_PARAM_free(params);
		BN_free(privKey);
		EVP_PKEY_free(old_key);

		if (!key) {
			printf("EVP_PKEY_fromdata err!\n");
			free(test_ctx);
			return NULL;
		}
	} else {}

	test_ctx->priv = key;
	test_ctx->key_size = setup.key_bits >> 3;

#ifdef DEBUG
	EVP_PKEY_print_private(stdout, key, 0, NULL);
#endif

	return test_ctx;
}


static struct ecc_test_ctx *ecxdh_create_hw_gen_test_ctx(struct ecc_test_ctx_setup setup, u32 op_type)
{
	struct ecc_test_ctx *test_ctx;
	struct wd_ecc_key *ecc_key;
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_req *req;
	handle_t sess = setup.sess;
	struct wd_dtb d;
	int ret;
	u32 key_size;

	req = malloc(sizeof(struct wd_ecc_req));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct wd_ecc_req));

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		HPRE_TST_PRT("%s: malloc fail!\n", __func__);
		goto free_req;
	}
	memset(test_ctx, 0, sizeof(struct ecc_test_ctx));

	key_size = (wd_ecc_get_key_bits(sess) + 7) / 8;
	test_ctx->cp_pub_key = malloc(2 * key_size);
	if (!test_ctx->cp_pub_key) {
		HPRE_TST_PRT("%s: malloc fail!\n", __func__);
		goto free_ctx;
	}

	ecc_out = wd_ecxdh_new_out(sess);
	if (!ecc_out) {
		HPRE_TST_PRT("%s: new ecc out fail!\n", __func__);
		goto free_cp_key;
	}

	ecc_key = wd_ecc_get_key(sess);

	if (setup.key_from || !setup.nid) {  // performance || async, the param is ready by curve
		if ((!g_is_set_prikey && is_async_test(op_type)) || !is_async_test(op_type)) {
			d.data = (void *)setup.priv_key;
			d.dsize = setup.priv_key_size;
			d.bsize = setup.priv_key_size;
			ret = wd_ecc_set_prikey(ecc_key, &d);
			if (ret) {
				HPRE_TST_PRT("%s: set prikey err\n", __func__);
				goto del_ecc_out;
			}
			g_is_set_prikey = true;
		}

		if (op_type >= X25519_GEN && op_type <= X448_ASYNC_COMPUTE) {
			memcpy(test_ctx->cp_pub_key, setup.pub_key, key_size);
			test_ctx->cp_pub_key_size = setup.pub_key_size;
		} else {
			memcpy(test_ctx->cp_pub_key, setup.pub_key + 1, key_size * 2);
			test_ctx->cp_pub_key_size = setup.pub_key_size - 1;
		}
	} else { // sync && not performance, the prikey/pubkey are from openssl
		if (op_type == X25519_GEN ||op_type == X25519_COMPUTE) { // x25519
			/* ret = x_genkey_by_openssl(test_ctx, ecc_key, key_size, 1);
			if (ret == 0) {
				return NULL;
			} */
		} else if (op_type == X448_GEN ||op_type == X448_COMPUTE) { // x448
			/* ret = x_genkey_by_openssl(test_ctx, ecc_key, key_size, 2);
			if (ret == 0) {
				return NULL;
			} */
		} else { // ecdh
			EVP_PKEY *key_a = NULL;
			EVP_PKEY_CTX *kctx = NULL;
			BIGNUM *d;
			struct wd_dtb dtb_d;
			char *tmp;
			size_t len;
			int gen_ret;

			kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
			if (!kctx) {
				printf("EVP_PKEY_CTX_new_from_name err!\n");
				goto del_ecc_out;
			}

			gen_ret = EVP_PKEY_keygen_init(kctx);
			if (gen_ret != 1) {
				printf("EVP_PKEY_keygen_init err!\n");
				EVP_PKEY_CTX_free(kctx);
				goto del_ecc_out;
			}

			gen_ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, setup.nid);
			if (gen_ret != 1) {
				printf("EVP_PKEY_CTX_set_ec_paramgen_curve_nid err!\n");
				EVP_PKEY_CTX_free(kctx);
				goto del_ecc_out;
			}

			gen_ret = EVP_PKEY_keygen(kctx, &key_a);
			EVP_PKEY_CTX_free(kctx);
			if (gen_ret != 1) {
				printf("EVP_PKEY_keygen err!\n");
				goto del_ecc_out;
			}

			gen_ret = EVP_PKEY_get_bn_param(key_a, OSSL_PKEY_PARAM_PRIV_KEY, &d);
			if (gen_ret != 1) {
				printf("EVP_PKEY_get_bn_param OSSL_PKEY_PARAM_PRIV_KEY err.\n");
				EVP_PKEY_free(key_a);
				goto del_ecc_out;
			}

			tmp = malloc(key_size);
			if (!tmp) {
				printf("malloc fail!\n");
				BN_free(d);
				EVP_PKEY_free(key_a);
				goto del_ecc_out;
			}

			memset(tmp, 0, key_size);
			dtb_d.dsize = BN_bn2bin(d, (void *)tmp);
			dtb_d.bsize = key_size;
			dtb_d.data = tmp;
			BN_free(d);
			gen_ret = wd_ecc_set_prikey(ecc_key, &dtb_d);
			if (gen_ret) {
				HPRE_TST_PRT("%s: set prikey err\n", __func__);
				EVP_PKEY_free(key_a);
				free(tmp);
				goto del_ecc_out;
			}
			free(tmp);

			gen_ret = EVP_PKEY_get_octet_string_param(key_a, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &len);
			if (gen_ret != 1 || len == 0) {
				printf("EVP_PKEY_get_octet_string_param OSSL_PKEY_PARAM_PUB_KEY err.\n");
				EVP_PKEY_free(key_a);
				goto del_ecc_out;
			}
			tmp = malloc(len);
			if (!tmp) {
				EVP_PKEY_free(key_a);
				goto del_ecc_out;
			}
			gen_ret = EVP_PKEY_get_octet_string_param(key_a, OSSL_PKEY_PARAM_PUB_KEY, tmp, len, &len);
			if (gen_ret != 1 || len < key_size * 2 + 1) {
				printf("EVP_PKEY_get_octet_string_param err.\n");
				EVP_PKEY_free(key_a);
				free(tmp);
				goto del_ecc_out;
			}
			memcpy(test_ctx->cp_pub_key, tmp + 1, 2 * key_size);
			test_ctx->cp_pub_key_size = len - 1;

			EVP_PKEY_free(key_a);
			free(tmp);
		}
	}

#ifdef DEBUG
	//struct wd_dtb *p;

	//wd_ecc_get_prikey_params(ecc_key, &p, NULL, NULL, NULL, NULL, NULL);
	//print_data(p->data, ECC_PRIKEY_SZ(p->bsize), "prikey");
	//print_data(test_ctx->cp_pub_key, test_ctx->cp_pub_key_size, "cp_pub_key");
#endif

	req->op_type = WD_ECXDH_GEN_KEY;
	req->dst = ecc_out;
	test_ctx->req = req;
	test_ctx->priv = (void *)sess;
	test_ctx->key_size = key_size;

	return test_ctx;

del_ecc_out:
	(void)wd_ecc_del_out(sess, ecc_out);
free_cp_key:
	free(test_ctx->cp_pub_key);
free_ctx:
	free(test_ctx);
free_req:
	free(req);

	return NULL;
}

static struct ecc_test_ctx *ecdh_create_sw_compute_test_ctx(struct ecc_test_ctx_setup setup, u32 optype)
{
	struct ecc_test_ctx *test_ctx;
	struct ecdh_sw_opdata *req;
	EVP_PKEY *key_a = NULL;
	EVP_PKEY *key_b = NULL;
	EVP_PKEY_CTX *kctx;
	int ret;

	if (ECDH_SW_COMPUTE != setup.op_type) {
		HPRE_TST_PRT("%s: err op type %d\n", __func__, setup.op_type);
		return NULL;
	}

	kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (!kctx) {
		printf("EVP_PKEY_CTX_new_from_name err!\n");
		return NULL;
	}

	ret = EVP_PKEY_keygen_init(kctx);
	if (ret != 1) {
		printf("EVP_PKEY_keygen_init err!\n");
		EVP_PKEY_CTX_free(kctx);
		return NULL;
	}

	ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, setup.nid);
	if (ret != 1) {
		printf("EVP_PKEY_CTX_set_ec_paramgen_curve_nid err!\n");
		EVP_PKEY_CTX_free(kctx);
		return NULL;
	}

	ret = EVP_PKEY_keygen(kctx, &key_a);
	EVP_PKEY_CTX_free(kctx);
	if (ret != 1) {
		printf("EVP_PKEY_keygen err!\n");
		return NULL;
	}

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		printf("malloc failed.\n");
			EVP_PKEY_free(key_a);
		return NULL;
	}

	req = malloc(sizeof(struct ecdh_sw_opdata));
	if (!req) {
		EVP_PKEY_free(key_a);
		free(test_ctx);
		return NULL;
	}

	memset(req, 0, sizeof(struct ecdh_sw_opdata));
	test_ctx->req = req;

	req->share_key = malloc((setup.key_bits >> 3) * 3);
	if (!req->share_key) {
		EVP_PKEY_free(key_a);
		free(test_ctx);
		return NULL;
	}
	req->share_key_size = (setup.key_bits >> 3) * 3;

	if (setup.key_from) {
		EVP_PKEY *old_key = key_a;
		OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
		OSSL_PARAM *params;

		if (!bld) {
			printf("OSSL_PARAM_BLD_new err!\n");
			EVP_PKEY_free(key_a);
			free(req->share_key);
			free(test_ctx);
			return NULL;
		}

		OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, OBJ_nid2sn(setup.nid), 0);
		if (setup.priv_key && setup.priv_key_size) {
			OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY, setup.priv_key, setup.priv_key_size);
		}
		if (setup.except_pub_key && setup.except_pub_key_size) {
			OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, setup.except_pub_key, setup.except_pub_key_size);
		}
		params = OSSL_PARAM_BLD_to_param(bld);
		OSSL_PARAM_BLD_free(bld);

		if (!params) {
			printf("OSSL_PARAM_BLD_to_param err!\n");
			EVP_PKEY_free(key_a);
			free(req->share_key);
			free(test_ctx);
			return NULL;
		}

		key_a = EVP_PKEY_fromdata(NULL, NULL, OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, params);
		OSSL_PARAM_free(params);
		EVP_PKEY_free(old_key);
		if (!key_a) {
			printf("EVP_PKEY_fromdata err!\n");
			free(req->share_key);
			free(test_ctx);
			return NULL;
		}
	} else {
		kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		if (!kctx) {
			printf("EVP_PKEY_CTX_new_from_name err!\n");
			EVP_PKEY_free(key_a);
			goto free_share_key;
		}
		EVP_PKEY_keygen_init(kctx);
		EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, setup.nid);
		ret = EVP_PKEY_keygen(kctx, &key_b);
		EVP_PKEY_CTX_free(kctx);
		if (ret != 1) {
			printf("EVP_PKEY_keygen err.\n");
			EVP_PKEY_free(key_a);
			goto free_share_key;
		}
	}

	test_ctx->priv = key_a;
	test_ctx->priv1 = key_b;
	test_ctx->key_size = setup.key_bits >> 3;

#ifdef DEBUG
	printf("except_pub_key:\n");
	EVP_PKEY_print_private(stdout, key_b, 0, NULL);
#endif
	EVP_PKEY_free(key_b);
	}
	// Note: EC_GROUP_free removed; EVP_PKEY handles group

#ifdef DEBUG
	EVP_PKEY_print_private(stdout, key_a, 0, NULL);
#endif
	return test_ctx;

free_share_key:
	free(req->share_key);
	EVP_PKEY_free(key_a);

	return NULL;
}

static struct ecc_test_ctx *ecxdh_create_hw_compute_test_ctx(struct ecc_test_ctx_setup setup, u32 op_type)
{
	struct ecc_test_ctx *test_ctx;
	struct wd_ecc_key *ecc_key;
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in;
	struct wd_ecc_req *req;
	struct wd_ecc_point tmp;
	struct wd_dtb d;
	int ret;
	u32 key_size;
	size_t len;

	req = malloc(sizeof(struct wd_ecc_req));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct wd_ecc_req));

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		HPRE_TST_PRT("%s: malloc fail!\n", __func__);
		goto free_req;
	}
	memset(test_ctx, 0, sizeof(struct ecc_test_ctx));

	key_size = (wd_ecc_get_key_bits(setup.sess) + 7) / 8;
	test_ctx->cp_share_key = malloc(key_size * 4);
	if (!test_ctx->cp_share_key) {
		HPRE_TST_PRT("%s: malloc fail!\n", __func__);
		goto free_ctx;
	}

	ecc_out = wd_ecxdh_new_out(setup.sess);
	if (!ecc_out) {
		goto free_cp_key;
	}

	ecc_key = wd_ecc_get_key(setup.sess);
	if (setup.key_from || !setup.nid) {
		if (op_type == X25519_GEN || op_type == X25519_COMPUTE ||
		    op_type == X448_GEN || op_type == X448_COMPUTE ||
		    op_type == X25519_ASYNC_GEN || op_type == X25519_ASYNC_COMPUTE ||
		    op_type == X448_ASYNC_GEN || op_type == X448_ASYNC_COMPUTE)
			tmp.x.data = setup.except_pub_key;
		else
			tmp.x.data = setup.except_pub_key + 1; // step 0x04

		tmp.x.bsize = key_size;
		tmp.x.dsize = key_size;
		tmp.y.data = tmp.x.data + key_size;
		tmp.y.bsize = key_size;
		tmp.y.dsize = key_size;
		ecc_in = wd_ecxdh_new_in(setup.sess, &tmp);
		if (!ecc_in) {
			goto del_ecc_out;
		}

		if ((!g_is_set_prikey && is_async_test(op_type)) || !is_async_test(op_type)) {
			d.data = (void *)setup.priv_key;
			d.dsize = setup.priv_key_size;
			d.bsize = setup.priv_key_size;
			ret = wd_ecc_set_prikey(ecc_key, &d);
			if (ret) {
				HPRE_TST_PRT("%s: set prikey err\n", __func__);
				goto del_ecc_in;
			}
			g_is_set_prikey = true;
		}

		memcpy(test_ctx->cp_share_key, setup.share_key, setup.share_key_size);
		test_ctx->cp_share_key_size = setup.share_key_size;
	} else {
		EVP_PKEY *key_a = NULL;
		EVP_PKEY_CTX *kctx = NULL;
		BIGNUM *d;
		struct wd_dtb dtb_d;
		char *buff;
		int gen_ret;
		size_t outlen;

		kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		if (!kctx) {
			printf("EVP_PKEY_CTX_new_from_name err!\n");
			goto del_ecc_out;
		}

		gen_ret = EVP_PKEY_keygen_init(kctx);
		if (gen_ret != 1) {
			printf("EVP_PKEY_keygen_init err!\n");
			EVP_PKEY_CTX_free(kctx);
			goto del_ecc_out;
		}

		gen_ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, setup.nid);
		if (gen_ret != 1) {
			printf("EVP_PKEY_CTX_set_ec_paramgen_curve_nid err!\n");
			EVP_PKEY_CTX_free(kctx);
			goto del_ecc_out;
		}

		gen_ret = EVP_PKEY_keygen(kctx, &key_a);
		EVP_PKEY_CTX_free(kctx);
		if (gen_ret != 1) {
			printf("EVP_PKEY_keygen err!\n");
			goto del_ecc_out;
		}

		gen_ret = EVP_PKEY_get_bn_param(key_a, OSSL_PKEY_PARAM_PRIV_KEY, &d);
		if (gen_ret != 1) {
			printf("EVP_PKEY_get_bn_param OSSL_PKEY_PARAM_PRIV_KEY err.\n");
			EVP_PKEY_free(key_a);
			goto del_ecc_out;
		}

		buff = malloc(key_size);
		if (!buff) {
			printf("malloc fail!\n");
			BN_free(d);
			EVP_PKEY_free(key_a);
			goto del_ecc_out;
		}

		dtb_d.dsize = BN_bn2bin(d, (void *)buff);
		dtb_d.bsize = key_size;
		dtb_d.data = buff;
		BN_free(d);
		gen_ret = wd_ecc_set_prikey(ecc_key, &dtb_d);
		if (gen_ret) {
			HPRE_TST_PRT("%s: set prikey err\n", __func__);
			EVP_PKEY_free(key_a);
			free(buff);
			goto del_ecc_out;
		}
		free(buff);

		/* Extract public key point for ecc_in */
		gen_ret = EVP_PKEY_get_octet_string_param(key_a, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &outlen);
		if (gen_ret != 1 || outlen == 0) {
			printf("EVP_PKEY_get_octet_string_param err.\n");
			EVP_PKEY_free(key_a);
			goto del_ecc_out;
		}
		buff = malloc(outlen);
		if (!buff) {
			EVP_PKEY_free(key_a);
			goto del_ecc_out;
		}
		gen_ret = EVP_PKEY_get_octet_string_param(key_a, OSSL_PKEY_PARAM_PUB_KEY, buff, outlen, &outlen);
		if (gen_ret != 1) {
			printf("EVP_PKEY_get_octet_string_param err.\n");
			EVP_PKEY_free(key_a);
			free(buff);
			goto del_ecc_out;
		}

		/* outlen should be 2*key_size+1 (uncompressed with 0x04) */
		tmp.x.data = buff + 1;
		tmp.x.dsize = key_size;
		tmp.x.bsize = key_size;
		tmp.y.data = tmp.x.data + key_size;
		tmp.y.dsize = key_size;
		tmp.y.bsize = key_size;
		ecc_in = wd_ecxdh_new_in(setup.sess, &tmp);
		if (!ecc_in) {
			printf("wd_ecc_new_in err.\n");
			EVP_PKEY_free(key_a);
			free(buff);
			goto del_ecc_out;
		}
		free(buff);

		#ifdef DEBUG
			//print_data(buff + 1, len - 1, "except_pub_key");
		#endif

		/* Use EVP_PKEY_derive approach for shared key */
		test_ctx->cp_share_key_size = key_size * 4;
		EVP_PKEY_free(key_a);
	}

#ifdef DEBUG
	//struct wd_dtb *p;

	//wd_ecc_get_prikey_params(ecc_key, &p, NULL, NULL, NULL, NULL, NULL);
	//print_data(p->data, ECC_PRIKEY_SZ(p->bsize), "prikey");
	//print_data(test_ctx->cp_share_key, test_ctx->cp_share_key_size, "cp_share_key");
#endif

	req->op_type = WD_ECXDH_COMPUTE_KEY;
	req->src = ecc_in;
	req->dst = ecc_out;
	test_ctx->req = req;
	test_ctx->priv = (void *)(setup.sess); //init sess
	test_ctx->key_size = key_size;

	return test_ctx;

del_ecc_in:
	(void)wd_ecc_del_in(setup.sess, ecc_in);
del_ecc_out:
	(void)wd_ecc_del_out(setup.sess, ecc_out);
free_cp_key:
	free(test_ctx->cp_pub_key);
free_ctx:
	free(test_ctx);
free_req:
	free(req);

	return NULL;
}

static struct ecc_test_ctx *sm2_create_hw_sign_test_ctx(struct ecc_test_ctx_setup setup, u32 op_type)
{
	__u8 is_dgst = g_config.msg_type == MSG_DIGEST;
	struct wd_ecc_req *req;
	struct ecc_test_ctx *test_ctx;
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in = NULL;
	handle_t sess = setup.sess;
	struct wd_dtb e, k, id;
	struct wd_dtb *kptr = NULL;
	struct wd_dtb *idptr = NULL;
	char buff[32] = {0};
	char *hex_str;
	u32 key_size;
	int ret;

	req = malloc(sizeof(struct wd_ecc_req));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct wd_ecc_req));

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		HPRE_TST_PRT("%s: malloc fail!\n", __func__);
		goto free_req;
	}
	memset(test_ctx, 0, sizeof(struct ecc_test_ctx));

	key_size = (wd_ecc_get_key_bits(sess) + 7) / 8;
	ecc_out = wd_sm2_new_sign_out(sess);
	if (!ecc_out) {
		HPRE_TST_PRT("%s: new ecc out fail!\n", __func__);
		goto free_ctx;
	}

	e.data = setup.msg;
	e.dsize = setup.msg_size;
	e.bsize = setup.msg_size;
	if (setup.key_from) {
		k.data = (void *)setup.k;
		k.dsize = setup.k_size;
		k.bsize = key_size;
		ecc_in = wd_sm2_new_sign_in(sess, &e, &k, NULL, 1);
		if (!ecc_in) {
			HPRE_TST_PRT("%s: new ecc in fail!\n", __func__);
			goto del_ecc_out;
		}
		
		memcpy(test_ctx->cp_sign, (void *)setup.sign, setup.sign_size);
		test_ctx->cp_sign_size = setup.sign_size;
	} else {
		EVP_MD_CTX *md_ctx = setup.openssl_handle;
		EVP_PKEY_CTX *pctx = EVP_MD_CTX_pkey_ctx(md_ctx);
		EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(pctx);

		if (g_config.rand_type == RAND_PARAM) {
			ret = hpre_get_rand(buff, 32, NULL);
			if (ret) {
				printf("hpre_get_rand failed\n");
				goto del_ecc_out;
			}
			k.data = buff;
			k.dsize = setup.k_size;
			kptr = &k;

			/* openssl set rand */
			hex_str = OPENSSL_buf2hexstr((void *)buff, 32);
			start_fake_rand(hex_str);
			OPENSSL_free(hex_str);
		}

		test_ctx->cp_sign_size = MAX_SIGN_LEN;
		if (g_config.msg_type == MSG_DIGEST) {
			ret = EVP_PKEY_sign_init(pctx);
			if (ret != 1) {
				printf("EVP_PKEY_sign_init fail, ret %d\n", ret);
				goto del_ecc_out;
			}

			ret = EVP_PKEY_sign(pctx, test_ctx->cp_sign, &test_ctx->cp_sign_size,
				setup.msg, setup.msg_size);
			if (ret != 1) {
				printf("EVP_PKEY_sign fail, ret %d\n", ret);
				goto del_ecc_out;
			}
		} else {
			id.data = (void *)setup.userid;
			id.dsize = setup.userid_size;
			idptr = &id;

			EVP_PKEY_CTX_set1_id(pctx, setup.userid, setup.userid_size);
			p_key = EVP_PKEY_CTX_get0_pkey(pctx);
			EVP_DigestSignInit(md_ctx, NULL, get_digest_handle(), NULL, p_key);
			EVP_DigestSignUpdate(md_ctx, setup.msg, setup.msg_size);
			ret = EVP_DigestSignFinal(md_ctx, test_ctx->cp_sign, &test_ctx->cp_sign_size);
			if (ret != 1) {
				printf("EVP_DigestSignFinal fail, ret %d\n", ret);
				goto del_ecc_out;
			}
		}

		evp_sign_to_hpre_bin((void *)test_ctx->cp_sign, &test_ctx->cp_sign_size, 32);
		ecc_in = wd_sm2_new_sign_in(sess, &e, kptr, idptr, is_dgst);
		if (!ecc_in) {
			HPRE_TST_PRT("%s: new ecc in fail!\n", __func__);
			goto del_ecc_out;
		}
	}

#ifdef DEBUG
	struct wd_ecc_key *ecc_key = wd_ecc_get_key(sess);
	struct wd_dtb *p;

	wd_ecc_get_prikey_params(ecc_key, &p, NULL, NULL, NULL, NULL, NULL);
	print_data(p->data, ECC_PRIKEY_SZ(p->bsize), "prikey");
	print_data(test_ctx->cp_sign, test_ctx->cp_sign_size, "cp_sign");
#endif

	req->op_type = WD_SM2_SIGN;
	req->dst = ecc_out;
	req->src = ecc_in;
	test_ctx->req = req;
	test_ctx->key_size = key_size;

	return test_ctx;

del_ecc_out:
	(void)wd_ecc_del_out(sess, ecc_out);
free_ctx:
	free(test_ctx);
free_req:
	free(req);

	return NULL;
}

static struct ecc_test_ctx *sm2_create_sw_sign_test_ctx(struct ecc_test_ctx_setup setup, u32 opType)
{
	return NULL;
}

static struct ecc_test_ctx *sm2_create_hw_verf_test_ctx(struct ecc_test_ctx_setup setup, u32 op_type)
{
	struct wd_ecc_req *req;
	struct wd_ecc_out *ecc_out;
	struct ecc_test_ctx *test_ctx;
	struct wd_ecc_in *ecc_in = NULL;
	handle_t sess = setup.sess;
	struct wd_dtb e, r, s, id;
	u32 key_size;
	int ret;

	req = malloc(sizeof(struct wd_ecc_req));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct wd_ecc_req));

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		HPRE_TST_PRT("%s: malloc fail!\n", __func__);
		goto free_req;
	}
	memset(test_ctx, 0, sizeof(struct ecc_test_ctx));

	key_size = (wd_ecc_get_key_bits(sess) + 7) / 8;
	ecc_out = wd_sm2_new_sign_out(sess);
	if (!ecc_out) {
		HPRE_TST_PRT("%s: new ecc out fail!\n", __func__);
		goto free_ctx;
	}


	e.data = setup.msg;
	e.dsize = setup.msg_size;
	e.bsize = key_size;
	if (setup.key_from) {
		r.data = (void *)setup.sign;
		r.dsize = key_size;
		r.bsize = key_size;
		s.data = r.data + key_size;
		s.dsize = key_size;
		s.bsize = key_size;
		ecc_in = wd_sm2_new_verf_in(sess, &e, &r, &s, NULL, 1);
		if (!ecc_in) {
			HPRE_TST_PRT("%s: new ecc in fail!\n", __func__);
			goto del_ecc_out;
		}
	} else {
		EVP_MD_CTX *md_ctx = setup.openssl_handle;
		EVP_PKEY_CTX *pctx = EVP_MD_CTX_pkey_ctx(md_ctx);
		EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(pctx);

		test_ctx->cp_sign_size = MAX_SIGN_LEN;
		id.data = (void *)setup.userid;
		id.dsize = setup.userid_size;
		EVP_PKEY_CTX_set1_id(pctx, setup.userid, setup.userid_size);
		p_key = EVP_PKEY_CTX_get0_pkey(pctx);
		EVP_DigestSignInit(md_ctx, NULL, get_digest_handle(), NULL, p_key);
		ret = EVP_DigestSign(md_ctx, test_ctx->cp_sign, &test_ctx->cp_sign_size,
			setup.msg, setup.msg_size);
		if (ret != 1) {
			printf("EVP_DigestSign fail, ret %d\n", ret);
			goto del_ecc_out;
		}

		evp_sign_to_hpre_bin((void *)test_ctx->cp_sign, &test_ctx->cp_sign_size, key_size);
		r.data = (void *)test_ctx->cp_sign;
		r.dsize = key_size;
		r.bsize = key_size;
		s.data = r.data + key_size;
		s.dsize = key_size;
		s.bsize = key_size;
		ecc_in = wd_sm2_new_verf_in(sess, &e, &r, &s, &id, 0);
		if (!ecc_in) {
			HPRE_TST_PRT("%s: new ecc in fail!\n", __func__);
			goto del_ecc_out;
		}
	}

#ifdef DEBUG
	struct wd_ecc_key *ecc_key = wd_ecc_get_key(sess);
	struct wd_dtb *p;

	wd_ecc_get_pubkey_params(ecc_key, &p, NULL, NULL, NULL, NULL, NULL);
	print_data(p->data, ECC_PRIKEY_SZ(p->bsize), "pubkey");
	print_data((void *)setup.userid, setup.userid_size, "userid");
	print_data(test_ctx->cp_sign, test_ctx->cp_sign_size, "openssl sign");
#endif

	req->op_type = WD_SM2_VERIFY;
	req->src = ecc_in;
	test_ctx->req = req;
	test_ctx->key_size = key_size;

	return test_ctx;

del_ecc_out:
	(void)wd_ecc_del_out(sess, ecc_out);
free_ctx:
	free(test_ctx);
free_req:
	free(req);

	return NULL;
}

static struct ecc_test_ctx *sm2_create_sw_verf_test_ctx(struct ecc_test_ctx_setup setup, u32 op_type)
{
	return NULL;
}

static struct ecc_test_ctx *sm2_create_hw_enc_test_ctx(struct ecc_test_ctx_setup setup, u32 op_type)
{
	struct wd_ecc_req *req;
	struct ecc_test_ctx *test_ctx;
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in = NULL;
	handle_t sess = setup.sess;
	struct wd_dtb e, k;
	struct wd_dtb *kptr = NULL;
	char buff[32] = {0};
	char *hex_str;
	u32 key_size;
	int ret;

	req = malloc(sizeof(struct wd_ecc_req));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct wd_ecc_req));

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		HPRE_TST_PRT("%s: malloc fail!\n", __func__);
		goto free_req;
	}
	memset(test_ctx, 0, sizeof(struct ecc_test_ctx));

	key_size = (wd_ecc_get_key_bits(sess) + 7) / 8;
	ecc_out = wd_sm2_new_enc_out(sess, setup.msg_size);
	if (!ecc_out) {
		HPRE_TST_PRT("%s: new ecc out fail!\n", __func__);
		goto free_ctx;
	}

	e.data = (void *)setup.msg;
	e.dsize = setup.msg_size;
	e.bsize = setup.msg_size;
	if (setup.key_from) {
		e.data = (void *)setup.plaintext;
		e.dsize = setup.plaintext_size;
		e.bsize = setup.plaintext_size;
		k.data = (void *)setup.k;
		k.dsize = setup.k_size;
		k.bsize = key_size;
		kptr = &k;
		memcpy(test_ctx->cp_enc, (void *)setup.ciphertext, setup.ciphertext_size);
		test_ctx->cp_enc_size = setup.ciphertext_size;
	} else if (g_config.rand_type == RAND_PARAM) {
		EVP_MD_CTX *md_ctx = setup.openssl_handle;
		EVP_PKEY_CTX *pctx = EVP_MD_CTX_pkey_ctx(md_ctx);

		ret = hpre_get_rand(buff, 32, NULL);
		if (ret) {
			printf("hpre_get_rand failed\n");
			goto del_ecc_out;
		}
		k.data = buff;
		k.dsize = setup.k_size;
		kptr = &k;

		/* openssl set rand */
		hex_str = OPENSSL_buf2hexstr((void *)buff, k.dsize);
		start_fake_rand(hex_str);
		OPENSSL_free(hex_str);

		EVP_PKEY_encrypt_init(pctx);
		EVP_PKEY_CTX_ctrl(pctx, -1, -1, EVP_PKEY_CTRL_MD, -1, (void *)get_digest_handle());
		test_ctx->cp_sign_size = MAX_SIGN_LEN;
		ret = EVP_PKEY_encrypt(pctx, test_ctx->cp_enc, &test_ctx->cp_enc_size,
			setup.msg, setup.msg_size);
		if (ret != 1) {
			printf("EVP_PKEY_encrypt fail, ret %d\n", ret);
			goto del_ecc_out;
		}

		#ifdef DEBUG
		struct wd_ecc_key *ecc_key = wd_ecc_get_key(sess);
		struct wd_dtb *p;

		wd_ecc_get_prikey_params(ecc_key, &p, NULL, NULL, NULL, NULL, NULL);
		print_data(p->data, ECC_PRIKEY_SZ(p->bsize), "pubkey");
		print_data(test_ctx->cp_enc, test_ctx->cp_enc_size, "cp_enc");
		#endif

		evp_to_wd_crypto((void *)test_ctx->cp_enc, &test_ctx->cp_enc_size, 32, setup.op_type);

		#ifdef DEBUG
		print_data(test_ctx->cp_enc, test_ctx->cp_enc_size, "cp_enc");
		#endif
	}

	ecc_in = wd_sm2_new_enc_in(sess, kptr, &e);
	if (!ecc_in) {
		HPRE_TST_PRT("%s: new ecc in fail!\n", __func__);
		goto del_ecc_out;
	}

	req->op_type = WD_SM2_ENCRYPT;
	req->dst = ecc_out;
	req->src = ecc_in;
	test_ctx->req = req;
	test_ctx->key_size = key_size;

	return test_ctx;

del_ecc_out:
	(void)wd_ecc_del_out(sess, ecc_out);
free_ctx:
	free(test_ctx);
free_req:
	free(req);

	return NULL;
}

static struct ecc_test_ctx *sm2_create_sw_enc_test_ctx(struct ecc_test_ctx_setup setup, u32 op_type)
{
	return NULL;
}

static struct ecc_test_ctx *sm2_create_hw_dec_test_ctx(struct ecc_test_ctx_setup setup, u32 op_type)
{
	struct wd_ecc_req *req;
	struct ecc_test_ctx *test_ctx;
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in = NULL;
	struct wd_ecc_point c1;
	struct wd_dtb c2, c3;
	handle_t sess = setup.sess;
	u32 key_size;
	int ret;

	req = malloc(sizeof(struct wd_ecc_req));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct wd_ecc_req));

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		HPRE_TST_PRT("%s: malloc fail!\n", __func__);
		goto free_req;
	}
	memset(test_ctx, 0, sizeof(struct ecc_test_ctx));

	key_size = (wd_ecc_get_key_bits(sess) + 7) / 8;


	if (setup.key_from) {
		c1.x.data = (void *)setup.ciphertext;
		c1.x.dsize = 32;
		c1.y.data = c1.x.data + 32;
		c1.y.dsize = 32;
		c3.data = c1.y.data + 32;
		c3.dsize = 32;
		c2.data = c3.data + 32;
		c2.dsize = setup.ciphertext_size - 32 * 3;
		ecc_in = wd_sm2_new_dec_in(sess, &c1, &c2, &c3);
		if (!ecc_in) {
			HPRE_TST_PRT("%s: new ecc in fail!\n", __func__);
			goto free_ctx;
		}
		memcpy(test_ctx->cp_enc, setup.plaintext, setup.plaintext_size);
		test_ctx->cp_enc_size = setup.plaintext_size;
	} else {
		EVP_MD_CTX *md_ctx = setup.openssl_handle;
		EVP_PKEY_CTX *pctx = EVP_MD_CTX_pkey_ctx(md_ctx);

		EVP_PKEY_encrypt_init(pctx);
		EVP_PKEY_CTX_ctrl(pctx, -1, -1, EVP_PKEY_CTRL_MD, -1, (void *)get_digest_handle());
		test_ctx->cp_enc_size = MAX_ENC_LEN;
		ret = EVP_PKEY_encrypt(pctx, (void *)test_ctx->cp_enc, &test_ctx->cp_enc_size,
			setup.msg, setup.msg_size);
		if (ret != 1) {
			printf("EVP_PKEY_encrypt fail, ret %d\n", ret);
			goto free_ctx;
		}

		#ifdef DEBUG
		print_data((void *)setup.msg, setup.msg_size, "msg");
		print_data(test_ctx->cp_enc, test_ctx->cp_enc_size, "cp_enc");
		#endif
		evp_to_wd_crypto((void *)test_ctx->cp_enc, &test_ctx->cp_enc_size, 32, SM2_HW_ENC);

		c1.x.data = (char *)test_ctx->cp_enc;
		c1.x.dsize = 32;
		c1.y.data = c1.x.data + 32;
		c1.y.dsize = 32;
		c3.data = c1.y.data + 32;
		c3.dsize = get_hash_bytes();
		c2.data = c3.data + c3.dsize;
		c2.dsize = setup.plaintext_size;
		ecc_in = wd_sm2_new_dec_in(sess, &c1, &c2, &c3);
		if (!ecc_in) {
			HPRE_TST_PRT("%s: new ecc in fail!\n", __func__);
			goto free_ctx;
		}

		memcpy(test_ctx->cp_enc, setup.msg, setup.msg_size);
		test_ctx->cp_enc_size = setup.msg_size;
	}

	ecc_out = wd_sm2_new_dec_out(sess, c2.dsize);
	if (!ecc_out) {
		HPRE_TST_PRT("%s: new ecc out fail!\n", __func__);
		goto free_ctx;
	}

	#ifdef DEBUG
	struct wd_ecc_key *ecc_key = wd_ecc_get_key(sess);
	struct wd_dtb *p;

	wd_ecc_get_prikey_params(ecc_key, &p, NULL, NULL, NULL, NULL, NULL);
	print_data(p->data, ECC_PRIKEY_SZ(p->bsize), "prikey");
	print_data(test_ctx->cp_enc, test_ctx->cp_enc_size, "cp_enc");
	#endif

	req->op_type = WD_SM2_DECRYPT;
	req->dst = ecc_out;
	req->src = ecc_in;
	test_ctx->req = req;
	test_ctx->key_size = key_size;

	return test_ctx;

free_ctx:
	free(test_ctx);
free_req:
	free(req);

	return NULL;
}

static struct ecc_test_ctx *sm2_create_sw_dec_test_ctx(struct ecc_test_ctx_setup setup, u32 op_type)
{
	return NULL;
}

static struct ecc_test_ctx *sm2_create_hw_kg_test_ctx(struct ecc_test_ctx_setup setup, u32 op_type)
{
	struct wd_ecc_req *req;
	struct ecc_test_ctx *test_ctx;
	struct wd_ecc_out *ecc_out;
	handle_t sess = setup.sess;
	u32 key_size;

	req = malloc(sizeof(struct wd_ecc_req));
	if (!req)
		return NULL;
	memset(req, 0, sizeof(struct wd_ecc_req));

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		HPRE_TST_PRT("%s: malloc fail!\n", __func__);
		goto free_req;
	}
	memset(test_ctx, 0, sizeof(struct ecc_test_ctx));

	key_size = (wd_ecc_get_key_bits(sess) + 7) / 8;
	ecc_out = wd_sm2_new_kg_out(sess);
	if (!ecc_out) {
		HPRE_TST_PRT("%s: new ecc out fail!\n", __func__);
		goto free_ctx;
	}

	if (setup.key_from) {
	} else {}


	req->op_type = WD_SM2_KG;
	req->dst = ecc_out;
	test_ctx->req = req;
	test_ctx->key_size = key_size;

	return test_ctx;

free_ctx:
	free(test_ctx);
free_req:
	free(req);

	return NULL;
}

static struct ecc_test_ctx *sm2_create_sw_kg_test_ctx(struct ecc_test_ctx_setup setup, u32 op_type)
{
	return NULL;
}

static struct ecc_test_ctx *ecc_create_sw_sign_test_ctx(struct ecc_test_ctx_setup setup, u32 optype)
{
	struct ecc_test_ctx *test_ctx;
	struct ecdh_sw_opdata *opdata;
	EVP_PKEY *key_a = NULL;
	EVP_PKEY_CTX *kctx;
	BIGNUM *kinv, *privKey, *rp;
	int size;
	int ret;

	if (ECC_SW_SIGN != setup.op_type) {
		HPRE_TST_PRT("%s: err op type %d\n", __func__, setup.op_type);
		return NULL;
	}

	kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (!kctx) {
		printf("EVP_PKEY_CTX_new_from_name err!\n");
		return NULL;
	}

	ret = EVP_PKEY_keygen_init(kctx);
	if (ret != 1) {
		printf("EVP_PKEY_keygen_init err!\n");
		EVP_PKEY_CTX_free(kctx);
		return NULL;
	}

	ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, setup.nid);
	if (ret != 1) {
		printf("EVP_PKEY_CTX_set_ec_paramgen_curve_nid err!\n");
		EVP_PKEY_CTX_free(kctx);
		return NULL;
	}

	ret = EVP_PKEY_keygen(kctx, &key_a);
	EVP_PKEY_CTX_free(kctx);
	if (ret != 1) {
		printf("EVP_PKEY_keygen err!\n");
		return NULL;
	}

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		printf("malloc failed.\n");
			EVP_PKEY_free(key_a);
		return NULL;
	}

	opdata = malloc(sizeof(struct ecdh_sw_opdata));
	if (!opdata) {
		EVP_PKEY_free(key_a);
		free(test_ctx);
		return NULL;
	}

	memset(opdata, 0, sizeof(struct ecdh_sw_opdata));
	test_ctx->req = opdata;
	size = EVP_PKEY_get_size(key_a);
	opdata->sign = malloc(size);
	memset(opdata->sign, 0, size);
	if (!opdata->sign) {
		EVP_PKEY_free(key_a);
		free(test_ctx);
		return NULL;
	}

	if (setup.key_from) {
		EVP_PKEY *old_key = key_a;
		OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
		OSSL_PARAM *params;

		if (!bld) {
			printf("OSSL_PARAM_BLD_new err!\n");
			EVP_PKEY_free(key_a);
			free(opdata->sign);
			free(test_ctx);
			return NULL;
		}

		opdata->except_e = setup.msg;
		opdata->except_e_size = setup.msg_size;
		kinv = BN_bin2bn((void *)setup.k, setup.k_size, NULL);
		opdata->except_kinv = kinv;
		rp = BN_bin2bn(setup.rp, setup.rp_size, NULL);
		opdata->except_rp = rp;

		OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, OBJ_nid2sn(setup.nid), 0);
		privKey = BN_bin2bn((void *)setup.priv_key, setup.priv_key_size, NULL);
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, privKey);
		params = OSSL_PARAM_BLD_to_param(bld);
		OSSL_PARAM_BLD_free(bld);

		if (!params) {
			printf("OSSL_PARAM_BLD_to_param err!\n");
			BN_free(privKey);
			EVP_PKEY_free(key_a);
			free(opdata->sign);
			free(test_ctx);
			return NULL;
		}

		key_a = EVP_PKEY_fromdata(NULL, NULL, OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, params);
		OSSL_PARAM_free(params);
		BN_free(privKey);
		EVP_PKEY_free(old_key);
		if (!key_a) {
			printf("EVP_PKEY_fromdata err!\n");
			free(opdata->sign);
			free(test_ctx);
			return NULL;
		}
	} else {}

	test_ctx->priv = key_a;
	test_ctx->key_size = setup.key_bits >> 3;
#ifdef DEBUG
	EVP_PKEY_print_private(stdout, key_a, 0, NULL);
#endif
	return test_ctx;
}

static struct ecc_test_ctx *ecc_create_sw_verf_test_ctx(struct ecc_test_ctx_setup setup, u32 optype)
{
	struct ecc_test_ctx *test_ctx;
	struct ecdh_sw_opdata *opdata;
	EVP_PKEY *key_a = NULL;
	EVP_PKEY_CTX *kctx;
	int ret;

	if (ECC_SW_VERF != setup.op_type) {
		HPRE_TST_PRT("%s: err op type %d\n", __func__, setup.op_type);
		return NULL;
	}

	kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (!kctx) {
		printf("EVP_PKEY_CTX_new_from_name err!\n");
		return NULL;
	}

	ret = EVP_PKEY_keygen_init(kctx);
	if (ret != 1) {
		printf("EVP_PKEY_keygen_init err!\n");
		EVP_PKEY_CTX_free(kctx);
		return NULL;
	}

	ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, setup.nid);
	if (ret != 1) {
		printf("EVP_PKEY_CTX_set_ec_paramgen_curve_nid err!\n");
		EVP_PKEY_CTX_free(kctx);
		return NULL;
	}

	ret = EVP_PKEY_keygen(kctx, &key_a);
	EVP_PKEY_CTX_free(kctx);
	if (ret != 1) {
		printf("EVP_PKEY_keygen err!\n");
		return NULL;
	}

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		printf("malloc failed.\n");
			EVP_PKEY_free(key_a);
		return NULL;
	}

	opdata = malloc(sizeof(struct ecdh_sw_opdata));
	if (!opdata) {
		EVP_PKEY_free(key_a);
		free(test_ctx);
		return NULL;
	}

	memset(opdata, 0, sizeof(struct ecdh_sw_opdata));
	test_ctx->req = opdata;

	if (setup.key_from) {
		EVP_PKEY *old_key = key_a;
		OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
		OSSL_PARAM *params;

		if (!bld) {
			printf("OSSL_PARAM_BLD_new err!\n");
			EVP_PKEY_free(key_a);
			free(test_ctx);
			return NULL;
		}

		opdata->except_e = (void *)setup.msg;
		opdata->except_e_size = setup.msg_size;
		opdata->sign = (void *)setup.sign;
		opdata->sign_size = setup.sign_size;

		OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, OBJ_nid2sn(setup.nid), 0);
		OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, setup.pub_key, setup.pub_key_size);
		params = OSSL_PARAM_BLD_to_param(bld);
		OSSL_PARAM_BLD_free(bld);

		if (!params) {
			printf("OSSL_PARAM_BLD_to_param err!\n");
			EVP_PKEY_free(key_a);
			free(test_ctx);
			return NULL;
		}

		key_a = EVP_PKEY_fromdata(NULL, NULL, OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, params);
		OSSL_PARAM_free(params);
		EVP_PKEY_free(old_key);
		if (!key_a) {
			printf("EVP_PKEY_fromdata err!\n");
			free(test_ctx);
			return NULL;
		}
	} else {}

	test_ctx->priv = key_a;
	test_ctx->key_size = setup.key_bits >> 3;
#ifdef DEBUG
	EVP_PKEY_print_private(stdout, key_a, 0, NULL);
#endif
	return test_ctx;
}

static struct ecc_test_ctx *ecc_create_hw_sign_test_ctx(struct ecc_test_ctx_setup setup, u32 op_type)
{

	struct wd_ecc_req *opdata;
	struct ecc_test_ctx *test_ctx;
	struct wd_ecc_key *ecc_key;
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in = NULL;
	struct wd_ecc_point pub;
	struct wd_dtb d, e, k;
	int ret;
	u32 key_size;

	opdata = malloc(sizeof(struct wd_ecc_req));
	if (!opdata)
		return NULL;
	memset(opdata, 0, sizeof(struct wd_ecc_req));

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		HPRE_TST_PRT("%s: malloc fail!\n", __func__);
		goto free_opdata;
	}
	memset(test_ctx, 0, sizeof(struct ecc_test_ctx));

	key_size = (wd_ecc_get_key_bits(setup.sess) + 7) / 8;
	ecc_out = wd_ecdsa_new_sign_out(setup.sess);
	if (!ecc_out) {
		HPRE_TST_PRT("%s: new ecc out fail!\n", __func__);
		goto free_ctx;
	}
	ecc_key = wd_ecc_get_key(setup.sess);
	if (!g_is_set_prikey || !is_async_test(op_type)) {
		d.data = (void *)setup.priv_key;
		d.dsize = setup.priv_key_size;
		d.bsize = setup.priv_key_size;
		ret = wd_ecc_set_prikey(ecc_key, &d);
		if (ret) {
			HPRE_TST_PRT("%s: set prikey err\n", __func__);
			goto del_ecc_out;
		}
		g_is_set_prikey = true;
	}

	if (!g_is_set_pubkey || !is_async_test(op_type)) {
		pub.x.data = (void *)setup.pub_key + 1;
		pub.x.dsize = key_size;
		pub.x.bsize = key_size;
		pub.y.data = pub.x.data + key_size;
		pub.y.dsize = key_size;
		pub.y.bsize = key_size;
		ret = wd_ecc_set_pubkey(ecc_key, &pub);
		if (ret) {
			HPRE_TST_PRT("%s: set pubkey err\n", __func__);
			goto del_ecc_out;
		}
		g_is_set_pubkey = true;
	}

	e.data = (void *)setup.msg;
	e.dsize = setup.msg_size;
	e.bsize = key_size;

	if (setup.key_from) {
		k.data = (void *)setup.k;
		k.dsize = setup.k_size;
		k.bsize = key_size;
		ecc_in = wd_ecdsa_new_sign_in(setup.sess, &e, &k);
		if (!ecc_in) {
			HPRE_TST_PRT("%s: new ecc in fail!\n", __func__);
			goto del_ecc_out;
		}
			} else {
			EVP_PKEY *key_a = NULL;
			EVP_PKEY_CTX *kctx;
			int gen_ret;

			kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
			if (!kctx) {
				printf("EVP_PKEY_CTX_new_from_name err!\n");
				goto del_ecc_out;
			}

			gen_ret = EVP_PKEY_keygen_init(kctx);
			if (gen_ret != 1) {
				printf("EVP_PKEY_keygen_init err!\n");
				EVP_PKEY_CTX_free(kctx);
				goto del_ecc_out;
			}

			gen_ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, setup.nid);
			if (gen_ret != 1) {
				printf("EVP_PKEY_CTX_set_ec_paramgen_curve_nid err!\n");
				EVP_PKEY_CTX_free(kctx);
				goto del_ecc_out;
			}

			gen_ret = EVP_PKEY_keygen(kctx, &key_a);
			EVP_PKEY_CTX_free(kctx);
			if (gen_ret != 1) {
				printf("EVP_PKEY_keygen err!\n");
				goto del_ecc_out;
			}

			ecc_in = wd_ecdsa_new_sign_in(setup.sess, &e, NULL);
			if (!ecc_in) {
				HPRE_TST_PRT("%s: new ecc in fail!\n", __func__);
				EVP_PKEY_free(key_a);
				goto del_ecc_out;
			}
		}

#ifdef DEBUG
	//struct wd_dtb *p;

	//wd_ecc_get_prikey_params(ecc_key, &p, NULL, NULL, NULL, NULL, NULL);
	//print_data(p->data, ECC_PRIKEY_SZ(p->bsize), "prikey");
	//print_data(test_ctx->cp_pub_key, test_ctx->cp_pub_key_size, "cp_pub_key");
#endif

	opdata->op_type = WD_ECDSA_SIGN;
	opdata->dst = ecc_out;
	opdata->src = ecc_in;
	test_ctx->req = opdata;
	test_ctx->priv = (void *)(setup.sess); //init ctx
	test_ctx->key_size = key_size;
	test_ctx->priv1 = key_a;

	return test_ctx;

del_ecc_out:
	(void)wd_ecc_del_out(setup.sess, ecc_out);
free_ctx:
	free(test_ctx);
free_opdata:
	free(opdata);

	return NULL;
}

static struct ecc_test_ctx *ecc_create_hw_verf_test_ctx(struct ecc_test_ctx_setup setup, u32 op_type)
{
	struct wd_ecc_req *opdata;
	struct ecc_test_ctx *test_ctx;
	struct wd_ecc_key *ecc_key;
	struct wd_ecc_in *ecc_in;
	ECDSA_SIG *sig;
	unsigned char buf1[100];
	unsigned char buf2[100];
	struct wd_dtb e, r, s;
	struct wd_ecc_point pub;
	int ret;
	u32 key_size;

	opdata = malloc(sizeof(struct wd_ecc_req));
	if (!opdata)
		return NULL;
	memset(opdata, 0, sizeof(struct wd_ecc_req));

	test_ctx = malloc(sizeof(struct ecc_test_ctx));
	if (!test_ctx) {
		HPRE_TST_PRT("%s: malloc fail!\n", __func__);
		goto free_opdata;
	}
	memset(test_ctx, 0, sizeof(struct ecc_test_ctx));

	key_size = (wd_ecc_get_key_bits(setup.sess) + 7) / 8;
	ecc_key = wd_ecc_get_key(setup.sess);
	if (!g_is_set_pubkey  || !is_async_test(op_type)) {
		pub.x.data = (void *)setup.pub_key + 1;
		pub.x.dsize = key_size;
		pub.x.bsize = key_size;
		pub.y.data = pub.x.data + key_size;
		pub.y.dsize = key_size;
		pub.y.bsize = key_size;
		ret = wd_ecc_set_pubkey(ecc_key, &pub);
		if (ret) {
			HPRE_TST_PRT("%s: set pubkey err\n", __func__);
			goto free_ctx;
		}
		g_is_set_pubkey = true;
	}

	e.data = (void *)setup.msg;
	e.dsize = setup.msg_size;
	e.bsize = key_size;

	if (setup.key_from) {
		r.data = (void *)setup.sign;
		r.dsize = key_size;
		r.bsize = key_size;
		s.data = r.data + key_size;
		s.dsize = key_size;
		s.bsize = key_size;
		ecc_in = wd_ecdsa_new_verf_in(setup.sess, &e, &r, &s);
		if (!ecc_in) {
			HPRE_TST_PRT("%s: new ecc in fail!\n", __func__);
			goto free_ctx;
		}
			} else {
			EVP_PKEY *key_a = NULL;
			EVP_PKEY_CTX *kctx;
			int gen_ret;

			kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
			if (!kctx) {
				printf("EVP_PKEY_CTX_new_from_name err!\n");
				goto free_ctx;
			}

			gen_ret = EVP_PKEY_keygen_init(kctx);
			if (gen_ret != 1) {
				printf("EVP_PKEY_keygen_init err!\n");
				EVP_PKEY_CTX_free(kctx);
				goto free_ctx;
			}

			gen_ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, setup.nid);
			if (gen_ret != 1) {
				printf("EVP_PKEY_CTX_set_ec_paramgen_curve_nid err!\n");
				EVP_PKEY_CTX_free(kctx);
				goto free_ctx;
			}

			gen_ret = EVP_PKEY_keygen(kctx, &key_a);
			EVP_PKEY_CTX_free(kctx);
			if (gen_ret != 1) {
				printf("EVP_PKEY_keygen err!\n");
				goto free_ctx;
			}

	/* openssl sign via EVP_PKEY, then parse DER to get r,s */
	EVP_PKEY_CTX *sign_ctx = EVP_PKEY_CTX_new(key_a, NULL);
	if (!sign_ctx) {
		printf("EVP_PKEY_CTX_new err!
");
		EVP_PKEY_free(key_a);
		goto free_ctx;
	}
	EVP_PKEY_sign_init(sign_ctx);
	size_t siglen;
	EVP_PKEY_sign(sign_ctx, NULL, &siglen, setup.degist, setup.degist_size);
	unsigned char *sigbuf = malloc(siglen);
	if (!sigbuf) {
		printf("malloc sigbuf fail!
");
		EVP_PKEY_free(key_a);
		EVP_PKEY_CTX_free(sign_ctx);
		goto free_ctx;
	}
	if (EVP_PKEY_sign(sign_ctx, sigbuf, &siglen, setup.degist, setup.degist_size) != 1) {
		printf("EVP_PKEY_sign failed
");
		EVP_PKEY_free(key_a);
		EVP_PKEY_CTX_free(sign_ctx);
		free(sigbuf);
		goto free_ctx;
	}
	EVP_PKEY_CTX_free(sign_ctx);
	/* Parse DER signature to get r,s */
	{
		const unsigned char *p = sigbuf;
		ECDSA_SIG *sig_tmp = d2i_ECDSA_SIG(NULL, &p, siglen);
		if (!sig_tmp) {
			printf("d2i_ECDSA_SIG failed
");
			EVP_PKEY_free(key_a);
			free(sigbuf);
			goto free_ctx;
		}
		const BIGNUM *b_r = ECDSA_SIG_get0_r(sig_tmp);
		const BIGNUM *b_s = ECDSA_SIG_get0_s(sig_tmp);
		ret = BN_bn2bin(b_r, buf1);
		r.data = (void *)buf1;
		r.dsize = ret;
		r.bsize = key_size;
		ret = BN_bn2bin(b_s, buf2);
		s.data = (void *)buf2;
		s.dsize = ret;
		s.bsize = key_size;
		ECDSA_SIG_free(sig_tmp);
	}
	free(sigbuf);
	ecc_in = wd_ecdsa_new_verf_in(setup.sess, &e, &r, &s);
	if (!ecc_in) {
		HPRE_TST_PRT("%s: new ecc in fail!
", __func__);
		EVP_PKEY_free(key_a);
		goto free_ctx;
	}
	EVP_PKEY_free(key_a);
}
#ifdef DEBUG
	//struct wd_dtb *p;

	//wd_get_ecc_prikey_params(ecc_key, &p, NULL, NULL, NULL, NULL, NULL);
	//print_data(p->data, ECC_PRIKEY_SZ(p->bsize), "prikey");
	//print_data(test_ctx->cp_pub_key, test_ctx->cp_pub_key_size, "cp_pub_key");
#endif

	opdata->op_type = WD_ECDSA_VERIFY;
	opdata->src = ecc_in;
	test_ctx->req = opdata;
	test_ctx->priv = (void *)(setup.sess); //init ctx
	test_ctx->key_size = key_size;

	return test_ctx;

free_ctx:
	free(test_ctx);
free_opdata:
	free(opdata);

	return NULL;
}

struct ecc_test_ctx *ecc_create_test_ctx(struct ecc_test_ctx_setup setup, u32 optype)
{
	struct ecc_test_ctx *test_ctx = NULL;

	switch (setup.op_type) {
		case ECDH_SW_GENERATE:
		{
			if (optype == ECDH_GEN || optype == ECDH_ASYNC_GEN) {
				test_ctx = ecdh_create_sw_gen_test_ctx(setup, optype);
			} else if (optype == X25519_GEN || optype == X25519_ASYNC_GEN ||
				   optype == X448_GEN || optype == X448_ASYNC_GEN) {
				//test_ctx = x_create_sw_gen_test_ctx(setup, optype);
			}
		}
		break;
		case ECDH_HW_GENERATE:
		{
			test_ctx = ecxdh_create_hw_gen_test_ctx(setup, optype);
		}
		break;
		case ECDH_SW_COMPUTE:
		{
			if (optype == ECDH_COMPUTE || optype == ECDH_ASYNC_COMPUTE) {
				test_ctx = ecdh_create_sw_compute_test_ctx(setup, optype);
			} else if (optype == X25519_COMPUTE || optype == X25519_ASYNC_COMPUTE ||
				optype == X448_COMPUTE || optype == X448_ASYNC_COMPUTE) {
				//test_ctx = x_create_sw_compute_test_ctx(setup, optype);
			}
		}
		break;
		case ECDH_HW_COMPUTE:
		{
			test_ctx = ecxdh_create_hw_compute_test_ctx(setup, optype);
		}
		break;
		case ECC_HW_SIGN:
		{
			test_ctx = ecc_create_hw_sign_test_ctx(setup, optype);
		}
		break;
		case ECC_HW_VERF:
		{
			test_ctx = ecc_create_hw_verf_test_ctx(setup, optype);
		}
		break;
		case ECC_SW_SIGN:
		{
			test_ctx = ecc_create_sw_sign_test_ctx(setup, optype);
		}
		break;
		case ECC_SW_VERF:
		{
			test_ctx = ecc_create_sw_verf_test_ctx(setup, optype);
		}
		break;
		case SM2_HW_SIGN:
		{
			test_ctx = sm2_create_hw_sign_test_ctx(setup, optype);
		}
		break;
		case SM2_HW_VERF:
		{
			test_ctx = sm2_create_hw_verf_test_ctx(setup, optype);
		}
		break;
		case SM2_SW_SIGN:
		{
			test_ctx = sm2_create_sw_sign_test_ctx(setup, optype);
		}
		break;
		case SM2_SW_VERF:
		{
			test_ctx = sm2_create_sw_verf_test_ctx(setup, optype);
		}
		break;

		case SM2_HW_ENC:
		{
			test_ctx = sm2_create_hw_enc_test_ctx(setup, optype);
		}
		break;
		case SM2_HW_DEC:
		{
			test_ctx = sm2_create_hw_dec_test_ctx(setup, optype);
		}
		break;
		case SM2_SW_ENC:
		{
			test_ctx = sm2_create_sw_enc_test_ctx(setup, optype);
		}
		break;
		case SM2_SW_DEC:
		{
			test_ctx = sm2_create_sw_dec_test_ctx(setup, optype);
		}
		break;
		case SM2_HW_KG:
		{
			test_ctx = sm2_create_hw_kg_test_ctx(setup, optype);
		}
		break;
		case SM2_SW_KG:
		{
			test_ctx = sm2_create_sw_kg_test_ctx(setup, optype);
		}
		break;
		default:
		break;
	}

	if (test_ctx)
		test_ctx->setup = setup;

	return test_ctx;
}

static int ecc_init_test_ctx_setup(struct ecc_test_ctx_setup *setup, __u32 op_type)
{
	u32 key_bits = g_config.key_bits;
	int key_size = (key_bits + 7) / 8;
	u32 len;

	if (op_type == ECDH_ASYNC_GEN || op_type == ECDH_ASYNC_COMPUTE) {
		setup->key_from = 1; // Designed
	} else {
		setup->key_from = g_config.data_from;
	}

	if (setup->key_from)
		HPRE_TST_PRT("Input data comes from fixed sample data\n");

	setup->key_bits = key_bits;

	if (setup->nid == 714 || key_bits == 256) { // NID_secp256k1
		/* sm2 */
		if (op_type == SM2_SIGN || op_type == SM2_VERF ||
			op_type == SM2_ENC || op_type == SM2_DEC || op_type == SM2_KG ||
			op_type == SM2_ASYNC_SIGN || op_type == SM2_ASYNC_VERF ||
			op_type == SM2_ASYNC_ENC || op_type == SM2_ASYNC_DEC || op_type == SM2_ASYNC_KG) {

			setup->priv_key = sm2_priv;
			setup->priv_key_size = sizeof(sm2_priv);
			setup->pub_key = sm2_pubkey;
			setup->pub_key_size = sizeof(sm2_pubkey);

			len = (g_config.msg_len == INVALID_LEN) ? MAX_ENC_LEN : g_config.msg_len;
			setup->msg = malloc(len);
			if (!setup->msg)
				return -1;
			memset(setup->msg, 0xFF, len);

			if (g_config.msg_type == MSG_DIGEST) {
				memcpy(setup->msg, sm2_digest, sizeof(sm2_digest));
				setup->msg_size = (g_config.msg_len == INVALID_LEN) ? sizeof(sm2_digest) : g_config.msg_len;
			} else {
				memcpy(setup->msg, sm2_plaintext, sizeof(sm2_plaintext));
				setup->msg_size = (g_config.msg_len == INVALID_LEN) ? sizeof(sm2_plaintext) : g_config.msg_len;
			}

			if (setup->msg_size > 512) {
				if (setup->msg_size != 513 && setup->key_from == 1)
					HPRE_TST_PRT("Sample data is fixed as 513 bytes\n");
				setup->ciphertext = sm2_ciphertext_l;
				setup->ciphertext_size = sizeof(sm2_ciphertext_l);
				setup->plaintext = sm2_plaintext_l;
				setup->plaintext_size = sizeof(sm2_plaintext_l);
			} else {
				setup->ciphertext = sm2_ciphertext;
				setup->ciphertext_size = sizeof(sm2_ciphertext);
				setup->plaintext = sm2_plaintext;
				setup->plaintext_size = sizeof(sm2_plaintext);
			}

			setup->k = sm2_k;
			setup->k_size = (g_config.k_len == INVALID_LEN) ? sizeof(sm2_k) : g_config.k_len;
			setup->userid = sm2_id;
			setup->userid_size = (g_config.id_len == INVALID_LEN) ? sizeof(sm2_id) : g_config.id_len;
			setup->sign = sm2_sign_data;
			setup->sign_size = sizeof(sm2_sign_data);

		} else {
			setup->priv_key = ecdh_da_secp256k1;
			setup->except_pub_key = ecdh_except_b_pubkey_secp256k1;
			setup->pub_key = ecdh_cp_pubkey_secp256k1;
			setup->share_key = ecdh_cp_sharekey_secp256k1;
			setup->priv_key_size = sizeof(ecdh_da_secp256k1);
			setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp256k1);
			setup->pub_key_size = sizeof(ecdh_cp_pubkey_secp256k1);
			setup->share_key_size = sizeof(ecdh_cp_sharekey_secp256k1);

			/* ecc sign */
			setup->msg = ecc_except_e_secp256k1;
			setup->msg_size = sizeof(ecc_except_e_secp256k1);
			setup->k = ecc_except_kinv_secp256k1;
			setup->k_size = sizeof(ecc_except_kinv_secp256k1);
			setup->rp = ecdh_cp_pubkey_secp256k1 + 1;
			setup->rp_size = key_size;

			/* ecc verf */
			setup->sign = ecc_cp_sign_secp256k1;
			setup->sign_size = sizeof(ecc_cp_sign_secp256k1);
		}
	} else if (setup->nid == 706 || key_bits == 128) {
		setup->priv_key = ecdh_da_secp128r1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp128r1;
		setup->pub_key = ecdh_cp_pubkey_secp128r1;
		setup->share_key = ecdh_cp_sharekey_secp128r1;
		setup->priv_key_size = sizeof(ecdh_da_secp128r1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp128r1);
		setup->pub_key_size = sizeof(ecdh_cp_pubkey_secp128r1);
		setup->share_key_size = sizeof(ecdh_cp_sharekey_secp128r1);

		/* ecc sign */
		setup->msg = ecc_except_e_secp128r1;
		setup->msg_size = sizeof(ecc_except_e_secp128r1);
		setup->k = ecc_except_kinv_secp128r1;
		setup->k_size = sizeof(ecc_except_kinv_secp128r1);
		setup->rp = ecdh_cp_pubkey_secp128r1 + 1;
		setup->rp_size = key_size;

		/* ecc verf */
		setup->sign = ecc_cp_sign_secp128r1;
		setup->sign_size = sizeof(ecc_cp_sign_secp128r1);

	} else if (setup->nid == 711 || key_bits == 192) {
		setup->priv_key = ecdh_da_secp192k1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp192k1;
		setup->pub_key = ecdh_cp_pubkey_secp192k1;
		setup->share_key = ecdh_cp_sharekey_secp192k1;
		setup->priv_key_size = sizeof(ecdh_da_secp192k1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp192k1);
		setup->pub_key_size = sizeof(ecdh_cp_pubkey_secp192k1);
		setup->share_key_size = sizeof(ecdh_cp_sharekey_secp192k1);

		/* ecc sign */
		setup->msg = ecc_except_e_secp192k1;
		setup->msg_size = sizeof(ecc_except_e_secp192k1);
		setup->k = ecc_except_kinv_secp192k1;
		setup->k_size = sizeof(ecc_except_kinv_secp192k1);
		setup->rp = ecdh_cp_pubkey_secp192k1 + 1;
		setup->rp_size = key_size;

		/* ecc verf */
		setup->sign = ecc_cp_sign_secp256k1;
		setup->sign_size = sizeof(ecc_cp_sign_secp256k1);
	} else if (setup->nid == 712 || g_config.key_bits == 224) {
		setup->priv_key = ecdh_da_secp224r1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp224r1;
		setup->pub_key = ecdh_cp_pubkey_secp224r1;
		setup->share_key = ecdh_cp_sharekey_secp224r1;
		setup->priv_key_size = sizeof(ecdh_da_secp224r1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp224r1);
		setup->pub_key_size = sizeof(ecdh_cp_pubkey_secp224r1);
		setup->share_key_size = sizeof(ecdh_cp_sharekey_secp224r1);
	} else if (setup->nid == 929 || key_bits == 320) {
		setup->priv_key = ecdh_da_secp320k1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp320k1;
		setup->pub_key = ecdh_cp_pubkey_secp320k1;
		setup->share_key = ecdh_cp_sharekey_secp320k1;
		setup->priv_key_size = sizeof(ecdh_da_secp320k1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp320k1);
		setup->pub_key_size = sizeof(ecdh_cp_pubkey_secp320k1);
		setup->share_key_size = sizeof(ecdh_cp_sharekey_secp320k1);

		/* ecc sign */
		setup->msg = ecc_except_e_secp320k1;
		setup->msg_size = sizeof(ecc_except_e_secp320k1);
		setup->k = ecc_except_kinv_secp320k1;
		setup->k_size = sizeof(ecc_except_kinv_secp320k1);
		setup->rp = ecdh_cp_pubkey_secp192k1 + 1;
		setup->rp_size = key_size;

		/* ecc verf */
		setup->sign = ecc_cp_sign_secp256k1;
		setup->sign_size = sizeof(ecc_cp_sign_secp256k1);

	} else if (setup->nid == 931 || key_bits == 384) {
		setup->priv_key = ecdh_da_secp384r1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp384r1;
		setup->pub_key = ecdh_cp_pubkey_secp384r1;
		setup->share_key = ecdh_cp_sharekey_secp384r1;
		setup->priv_key_size = sizeof(ecdh_da_secp384r1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp384r1);
		setup->pub_key_size = sizeof(ecdh_cp_pubkey_secp384r1);
		setup->share_key_size = sizeof(ecdh_cp_sharekey_secp384r1);

		/* ecc sign */
		setup->msg = ecc_except_e_secp384r1;
		setup->msg_size = sizeof(ecc_except_e_secp384r1);
		setup->k = ecc_except_kinv_secp384r1;
		setup->k_size = sizeof(ecc_except_kinv_secp384r1);
		setup->rp = ecdh_cp_pubkey_secp384r1 + 1;
		setup->rp_size = key_size;

		/* ecc verf */
		setup->sign = ecc_cp_sign_secp256k1;
		setup->sign_size = sizeof(ecc_cp_sign_secp256k1);
	} else if (setup->nid == 716 || key_bits == 521) {
		setup->priv_key = ecdh_da_secp521r1;
		setup->except_pub_key = ecdh_except_b_pubkey_secp521r1;
		setup->pub_key = ecdh_cp_pubkey_secp521r1;
		setup->share_key = ecdh_cp_sharekey_secp521r1;
		setup->priv_key_size = sizeof(ecdh_da_secp521r1);
		setup->except_pub_key_size = sizeof(ecdh_except_b_pubkey_secp521r1);
		setup->pub_key_size = sizeof(ecdh_cp_pubkey_secp521r1);
		setup->share_key_size = sizeof(ecdh_cp_sharekey_secp521r1);

		/* ecc sign */
		setup->msg = ecc_except_e_secp521r1;
		setup->msg_size = sizeof(ecc_except_e_secp521r1);
		setup->k = ecc_except_kinv_secp521r1;
		setup->k_size = sizeof(ecc_except_kinv_secp521r1);
		setup->rp = ecdh_cp_pubkey_secp521r1 + 1;
		setup->rp_size = key_size;

		/* ecc verf */
		setup->sign = ecc_cp_sign_secp256k1;
		setup->sign_size = sizeof(ecc_cp_sign_secp256k1);

	} else {
		HPRE_TST_PRT("init test sess setup not find this bits %d or nid %d\n",
				key_bits, setup->nid);
		return -1;
	}

	return 0;
}


static int ecxdh_generate_key(void *test_ctx, void *tag)
{
	struct ecc_test_ctx *t_c = test_ctx;
	int ret = 0;

	if (t_c->setup.op_type == ECDH_SW_GENERATE) {
#if 0  // x25519/x448, add later
		if (t_c->is_x25519_x448){
			EVP_PKEY_METHOD *pmeth;
			EVP_PKEY_CTX pkey_ctx;
			size_t key_sz;
			EVP_PKEY pkey;
			ECX_KEY ecx;

			memset(&pkey_ctx, 0, sizeof(EVP_PKEY_CTX));
			memset(&pkey, 0, sizeof(EVP_PKEY));
			memset(&ecx, 0, sizeof(ECX_KEY));

			if (t_c->key_size == 32) { // x25519
				pmeth = EVP_PKEY_meth_find(EVP_PKEY_X25519);
				ecx.privkey = x25519_aprikey;
				memcpy(ecx.pubkey, x25519_x_param, 32);
			} else { // if (t_c->key_size == 56) { // x448
				pmeth = EVP_PKEY_meth_find(EVP_PKEY_X448);
				ecx.privkey = x448_aprikey;
				memcpy(ecx.pubkey, x448_x_param, 56);
			}
			pkey.pkey.ecx = &ecx;
			pkey_ctx.pkey = &pkey;
			pkey_ctx.peerkey = &pkey;

			uint8_t *out_pub_key = calloc(t_c->key_size, sizeof(char));

			ret = pmeth->derive(&pkey_ctx, out_pub_key, &key_sz);
			if (ret == 0) {
				HPRE_TST_PRT("%s: pmeth->derive err.\n", __func__);
				return -1;
			}
			#if 0
			int i;
			for (i = 0; i < t_c->key_size; i++) {
				if (i % 12 == 0)
					printf("\n");
				printf("0x%x, ", out_pub_key[i]);
			}printf("\n");
			#endif
			free(out_pub_key);
		} else
#endif
		{
			// Key already generated by EVP_PKEY_keygen during context creation
#ifdef DEBUG
			EVP_PKEY_print_private(stdout, t_c->priv, 0, NULL);
#endif
		}
	} else {
		struct wd_ecc_req *req = t_c->req;
		handle_t sess = (handle_t)t_c->priv;
try_again:
		if (tag)
			ret = wd_do_ecc_async(sess, req);
		else
			ret = wd_do_ecc_sync(sess, req);
		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_again;
		} else if (ret) {
			HPRE_TST_PRT("wd_do_ecc fail!\n");
			return -1;
		}
	}

	return 0;
}


static int ecxdh_compute_key(void *test_ctx, void *tag)
{
	struct ecc_test_ctx *t_c = test_ctx;
	int ret = 0;

	if (t_c->setup.op_type == ECDH_SW_COMPUTE) {
#if 0
		if (t_c->is_x25519_x448){
			EVP_PKEY_METHOD *pmeth;
			EVP_PKEY_CTX pkey_ctx;
			EVP_PKEY pkey;
			ECX_KEY ecx;
			size_t key_sz;
			int ret;

			memset(&pkey_ctx, 0, sizeof(EVP_PKEY_CTX));
			memset(&pkey, 0, sizeof(EVP_PKEY));
			memset(&ecx, 0, sizeof(ECX_KEY));

			if (t_c->key_size == 32) { // x25519
				pmeth = EVP_PKEY_meth_find(EVP_PKEY_X25519);
				ecx.privkey = x25519_aprikey;
				memcpy(ecx.pubkey, x25519_bpubkey, 32);
			} else { // if (t_c->key_size == 56) { // x448
				pmeth = EVP_PKEY_meth_find(EVP_PKEY_X448);
				ecx.privkey = x448_aprikey;
				memcpy(ecx.pubkey, x448_bpubkey, 56);
			}
			pkey.pkey.ecx = &ecx;
			pkey_ctx.pkey = &pkey;
			pkey_ctx.peerkey = &pkey;

			uint8_t *out_shared_key = calloc(t_c->key_size, sizeof(char));

			ret = pmeth->derive(&pkey_ctx, out_shared_key, &key_sz);
			if (ret <= 0) {
				HPRE_TST_PRT("%s: pmeth->derive err.\n", __func__);
				return -1;
			}
			#if 0
			int i;
			for (i = 0; i < t_c->key_size; i++) {
				if (i % 12 == 0)
					printf("\n");
				printf("0x%x, ", out_shared_key[i]);
			}printf("\n");
			#endif
			free(out_shared_key);
		} else {
#endif
		struct ecdh_sw_opdata *req = t_c->req;
		EVP_PKEY *ec_key = t_c->priv;
		EVP_PKEY *peer_key = t_c->priv1;
		EVP_PKEY_CTX *dctx;

		dctx = EVP_PKEY_CTX_new(ec_key, NULL);
		if (!dctx) {
			HPRE_TST_PRT("EVP_PKEY_CTX_new fail!\n");
			return -1;
		}
		ret = EVP_PKEY_derive_init(dctx);
		if (ret != 1) {
			HPRE_TST_PRT("EVP_PKEY_derive_init fail!\n");
			EVP_PKEY_CTX_free(dctx);
			return -1;
		}
		if (peer_key) {
			ret = EVP_PKEY_derive_set_peer(dctx, peer_key);
			if (ret != 1) {
				HPRE_TST_PRT("EVP_PKEY_derive_set_peer fail!\n");
				EVP_PKEY_CTX_free(dctx);
				return -1;
			}
		}
		ret = EVP_PKEY_derive(dctx, req->share_key, (size_t *)&req->share_key_size);
		if (ret != 1) {
			HPRE_TST_PRT("EVP_PKEY_derive fail!\n");
			EVP_PKEY_CTX_free(dctx);
			return -1;
		}
		EVP_PKEY_CTX_free(dctx);
		//}
#ifdef DEBUG
	//ECParameters_print_fp(stdout, ec_key);
	//print_data(req->share_key, ret, "openssl share key");

#endif
	} else {
		struct wd_ecc_req *req = t_c->req;
		handle_t sess = (handle_t)t_c->priv;
try_again:

		if (tag)
			ret = wd_do_ecc_async(sess, req);
		else
			ret = wd_do_ecc_sync(sess, req);

		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_again;
		} else if (ret) {
			HPRE_TST_PRT("wd_do_ecc fail!\n");
			return -1;
		}
#ifdef DEBUG
		//print_data(req->pri, req->pri_bytes,"hpre share key");
#endif
	}

	return 0;
}

int ecdsa_sign(void *test_ctx, void *tag)
{
	struct ecc_test_ctx *t_c = test_ctx;
	int ret = 0;

	if (t_c->setup.op_type == ECC_SW_SIGN) {
		EVP_PKEY *ec_key = t_c->priv;
		struct ecdh_sw_opdata *opdata = t_c->req;
		EVP_PKEY_CTX *sctx;

		sctx = EVP_PKEY_CTX_new(ec_key, NULL);
		if (!sctx) {
			HPRE_TST_PRT("EVP_PKEY_CTX_new fail!\n");
			return -1;
		}

		ret = EVP_PKEY_sign_init(sctx);
		if (ret != 1) {
			HPRE_TST_PRT("EVP_PKEY_sign_init fail!\n");
			EVP_PKEY_CTX_free(sctx);
			return -1;
		}

		ret = EVP_PKEY_sign(sctx, opdata->sign, &opdata->sign_size,
			opdata->except_e, opdata->except_e_size);
		if (ret != 1) {
			HPRE_TST_PRT("EVP_PKEY_sign fail!\n");
			EVP_PKEY_CTX_free(sctx);
			return -1;
		}
		EVP_PKEY_CTX_free(sctx);

#ifdef DEBUG
		print_data(opdata->sign, opdata->sign_size, "openssl sign");
		EVP_PKEY_print_private(stdout, ec_key, 0, NULL);
#endif

	} else {
		struct wd_ecc_req *opdata = t_c->req;
		handle_t sess = (handle_t)t_c->priv;
try_again:
		if (tag)
			ret = wd_do_ecc_async(sess, opdata);
		else
			ret = wd_do_ecc_sync(sess, opdata);
		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_again;
		} else if (ret) {
			HPRE_TST_PRT("wd_do_ecc fail!\n");
			return -1;
		}

		if (tag)
			return 0;
#ifdef DEBUG
	struct wd_dtb *r, *s;
	wd_ecdsa_get_sign_out_params(opdata->dst, &r, &s);
	print_data(r->data, r->dsize, "hpre r");
	print_data(s->data, s->dsize, "hpre s");
#endif
	}

	return 0;
}

int ecdsa_verf(void *test_ctx, void *tag)
{
	struct ecc_test_ctx *t_c = test_ctx;
	int ret = 0;

	if (t_c->setup.op_type == ECC_SW_VERF) {
		EVP_PKEY *ec_key = t_c->priv;
		struct ecdh_sw_opdata *opdata = t_c->req;
		EVP_PKEY_CTX *vctx;

		vctx = EVP_PKEY_CTX_new(ec_key, NULL);
		if (!vctx) {
			HPRE_TST_PRT("EVP_PKEY_CTX_new fail!\n");
			return -1;
		}

		ret = EVP_PKEY_verify_init(vctx);
		if (ret != 1) {
			HPRE_TST_PRT("EVP_PKEY_verify_init fail!\n");
			EVP_PKEY_CTX_free(vctx);
			return -1;
		}

		ret = EVP_PKEY_verify(vctx, opdata->sign, opdata->sign_size,
			opdata->except_e, opdata->except_e_size);
		if (ret != 1) {
			HPRE_TST_PRT("EVP_PKEY_verify fail = %d!\n", ret);
			EVP_PKEY_CTX_free(vctx);
			return -1;
		}
		EVP_PKEY_CTX_free(vctx);

#ifdef DEBUG
		EVP_PKEY_print_private(stdout, ec_key, 0, NULL);
#endif

	} else {
		struct wd_ecc_req *opdata = t_c->req;
		handle_t sess = (handle_t)t_c->priv;
try_again:
		if (tag)
			ret = wd_do_ecc_async(sess, opdata);
		else
			ret = wd_do_ecc_sync(sess, opdata);
		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_again;
		} else if (ret) {
			//HPRE_TST_PRT("wd_do_ecc fail!\n");
			//return -1;
		}

#ifdef DEBUG
	printf("hpre verf = %d\n", opdata->status);
#endif
	}

	return 0;
}

static int sm2_sign(void *test_ctx, void *pTag)
{
	struct ecc_test_ctx *t_c = test_ctx;
	int ret = 0;

	if (t_c->setup.op_type == ECC_SW_SIGN) {
		EVP_PKEY *ec_key = t_c->priv;
		struct ecdh_sw_opdata *opdata = t_c->req;
		EVP_PKEY_CTX *sctx;

		sctx = EVP_PKEY_CTX_new(ec_key, NULL);
		if (!sctx) {
			HPRE_TST_PRT("EVP_PKEY_CTX_new fail!\n");
			return -1;
		}

		ret = EVP_PKEY_sign_init(sctx);
		if (ret != 1) {
			HPRE_TST_PRT("EVP_PKEY_sign_init fail!\n");
			EVP_PKEY_CTX_free(sctx);
			return -1;
		}

		ret = EVP_PKEY_sign(sctx, opdata->sign, &opdata->sign_size,
			opdata->except_e, opdata->except_e_size);
		if (ret != 1) {
			HPRE_TST_PRT("EVP_PKEY_sign fail!\n");
			EVP_PKEY_CTX_free(sctx);
			return -1;
		}
		EVP_PKEY_CTX_free(sctx);

#ifdef DEBUG
		print_data(opdata->sign, opdata->sign_size, "openssl sign");
		EVP_PKEY_print_private(stdout, ec_key, 0, NULL);
#endif

	} else {
		struct wd_ecc_req *req = t_c->req;
		handle_t sess = t_c->setup.sess;
try_again:
		if (pTag)
			ret = wd_do_ecc_async(sess, req);
		else
			ret = wd_do_ecc_sync(sess, req);
		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_again;
		} else if (ret) {
			HPRE_TST_PRT("wd_do_ecc fail, ret = %d!\n", ret);
			return -1;
		}

#ifdef DEBUG
	struct wd_dtb *r, *s;
	wd_sm2_get_sign_out_params(req->dst, &r, &s);
	print_data(r->data, r->dsize, "hpre r");
	print_data(s->data, s->dsize, "hpre s");
#endif
	}

	return 0;
}

static int sm2_verf(void *test_ctx, void *pTag)
{
	struct ecc_test_ctx *t_c = test_ctx;
	int ret = 0;

	if (t_c->setup.op_type == ECC_SW_VERF) {
	} else {
		struct wd_ecc_req *req = t_c->req;
		handle_t sess = t_c->setup.sess;
try_again:
		if (pTag)
			ret = wd_do_ecc_async(sess, req);
		else
			ret = wd_do_ecc_sync(sess, req);
		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_again;
		} else if (ret) {
			HPRE_TST_PRT("wd_do_ecc fail, ret = %d!\n", ret);
			return -1;
		}

#ifdef DEBUG
	printf("hpre verf = %d\n", req->status);
#endif
	}

	return 0;
}

static int sm2_enc(void *test_ctx, void *pTag)
{
	struct ecc_test_ctx *t_c = test_ctx;
	int ret = 0;

	if (t_c->setup.op_type == SM2_SW_ENC) {
	} else {
		struct wd_ecc_req *req = t_c->req;
		handle_t sess = t_c->setup.sess;
try_again:
		if (pTag)
			ret = wd_do_ecc_async(sess, req);
		else
			ret = wd_do_ecc_sync(sess, req);
		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_again;
		} else if (ret) {
			HPRE_TST_PRT("wd_do_ecc fail, ret = %d!\n", ret);
			return -1;
		}

#ifdef DEBUG
	printf("hpre enc = %d\n", req->status);
#endif
	}

	return 0;
}

static int sm2_dec(void *test_ctx, void *pTag)
{
	struct ecc_test_ctx *t_c = test_ctx;
	int ret = 0;

	if (t_c->setup.op_type == SM2_SW_ENC) {
	} else {
		struct wd_ecc_req *req = t_c->req;
		handle_t sess = t_c->setup.sess;
try_again:
		if (pTag)
			ret = wd_do_ecc_async(sess, req);
		else
			ret = wd_do_ecc_sync(sess, req);
		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_again;
		} else if (ret) {
			HPRE_TST_PRT("wd_do_ecc fail, ret = %d!\n", ret);
			return -1;
		}

#ifdef DEBUG
	printf("hpre dec = %d\n", req->status);
#endif
	}

	return 0;
}

static int sm2_kg(void *test_ctx, void *pTag)
{
	struct ecc_test_ctx *t_c = test_ctx;
	int ret = 0;

	if (t_c->setup.op_type == SM2_SW_ENC) {
	} else {
		struct wd_ecc_req *req = t_c->req;
		handle_t sess = t_c->setup.sess;
try_again:
		if (pTag)
			ret = wd_do_ecc_async(sess, req);
		else
			ret = wd_do_ecc_sync(sess, req);
		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_again;
		} else if (ret) {
			HPRE_TST_PRT("wd_do_ecc fail, ret = %d!\n", ret);
			return -1;
		}

#ifdef DEBUG
	printf("hpre kg = %d\n", req->status);
#endif
	}

	return 0;
}

int ecc_point1buf(struct wd_ecc_point *in, int ksz, void *buf, int bsz)
{
	struct wd_dtb *x;
	int ret = 0;

	if (!buf || !in)
		return -1;

	x = &in->x;

	ret = x->dsize;
	if (ret > bsz)
		return -1;

	memcpy(buf, x->data, x->dsize);

	return ret;
}

int ecc_point2buf(struct wd_ecc_point *in, int ksz, void *buf, int bsz)
{
	struct wd_dtb *x, *y;
	int ret = 0;

	if (!buf || !in)
		return -1;

	x = &in->x;
	y = &in->y;

	ret = x->dsize + y->dsize;
	if (ret > bsz)
		return -1;
#ifdef DEBUG
	//print_data(x->data, x->dsize, "x");
	//print_data(y->data, y->dsize, "y");
#endif
	memcpy(buf, x->data, x->dsize);
	memcpy(buf + x->dsize, y->data, y->dsize);

	return ret;
}

static int ecdsa_sign_result_check(struct ecc_test_ctx *test_ctx, __u8 is_async)
{
	return 0;
}

static int sm2_sign_result_check(struct ecc_test_ctx *test_ctx, __u8 is_async)
{
	struct wd_ecc_req *req = test_ctx->req;
	struct wd_dtb prk, pbk;
	EVP_MD_CTX *md_ctx;
	EVP_PKEY_CTX *pctx;
	EVP_PKEY *p_key;
	struct wd_dtb *r, *s;
	char buff[MAX_SIGN_LEN] = {0};
	size_t len;
	int ret;

	wd_sm2_get_sign_out_params(req->dst, &r, &s);
	memcpy(buff, r->data, s->dsize);
	crypto_bin_to_hpre_bin(buff, r->data, r->bsize, r->dsize);
	memcpy(buff + 32, s->data, s->dsize);
	crypto_bin_to_hpre_bin(buff + 32, s->data, s->bsize, s->dsize);

	if (g_config.rand_type != RAND_PARAM && !test_ctx->setup.key_from) {
		pbk.data = (void *)test_ctx->setup.pub_key;
		pbk.dsize = test_ctx->setup.pub_key_size;
		prk.data = (void *)test_ctx->setup.priv_key;
		prk.dsize = test_ctx->setup.priv_key_size;
		md_ctx = ecc_create_openssl_handle(&prk, &pbk);
		if (!md_ctx)
			return -1;
		pctx = EVP_MD_CTX_pkey_ctx(md_ctx);
		p_key = EVP_PKEY_CTX_get0_pkey(pctx);

		/* openssl verf check */
		len = hpre_bin_sign_to_evp(buff, buff, 32);
		if (g_config.msg_type == MSG_DIGEST) {
			ret = EVP_PKEY_verify_init(pctx);
			if (ret != 1) {
				HPRE_TST_PRT("EVP_PKEY_verify_init fail, ret = %d!\n", ret);
				return -1;
			}

			ret = EVP_PKEY_verify(pctx, (void *)buff, len,
				test_ctx->setup.msg, test_ctx->setup.msg_size);
		} else {
			EVP_PKEY_CTX_set1_id(pctx, test_ctx->setup.userid,
				test_ctx->setup.userid_size);
			EVP_DigestVerifyInit(md_ctx, NULL, get_digest_handle(), NULL, p_key);
			EVP_DigestVerifyUpdate(md_ctx, test_ctx->setup.msg, test_ctx->setup.msg_size);
			ret = EVP_DigestVerifyFinal(md_ctx, (void *)buff, len);
		}
		if (ret != 1) {
			HPRE_TST_PRT("openssl verf fail, ret = %d!\n", ret);
			print_data(buff, len, "hpre sign");
			print_data((void *)test_ctx->setup.msg, test_ctx->setup.msg_size, "msg");
			EVP_PKEY_print_private(stdout, p_key, 0, NULL);
			return -1;
		}

		ecc_del_openssl_handle(md_ctx);
#ifdef DEBUG
			HPRE_TST_PRT("sm2 verf pass!\n");
#endif

	} else {
		if (memcmp(test_ctx->cp_sign, buff, test_ctx->cp_sign_size)) {
			HPRE_TST_PRT("sm2 op %d mismatch!\n", test_ctx->setup.op_type);
			print_data(buff, 64, "hpre out");
			print_data(test_ctx->cp_sign, test_ctx->cp_sign_size, "openssl out");
			return -1;
		}
	}

	return 0;
}

static int sm2_enc_result_check(struct ecc_test_ctx *test_ctx, __u8 is_async)
{
	struct wd_ecc_req *req = test_ctx->req;
	EVP_MD_CTX *md_ctx;
	EVP_PKEY_CTX *pctx;
	struct wd_ecc_point *c1 = NULL;
	struct wd_dtb *c2 = NULL, *c3 = NULL;
	struct wd_dtb pbk, prk;
	char *buf, *ptext;
	size_t lens = 0;
	__u32 evp_len;
	int ret;

	buf = malloc(MAX_ENC_LEN);
	if (!buf) {
		HPRE_TST_PRT("malloc buf failed\n");
		return -1;
	}

	ptext = malloc(MAX_ENC_LEN);
	if (!buf) {
		HPRE_TST_PRT("malloc ptext failed\n");
		return -1;
	}

	memset(buf, 0, MAX_ENC_LEN);
	memset(ptext, 0, MAX_ENC_LEN);
	lens = MAX_ENC_LEN;
	wd_sm2_get_enc_out_params(req->dst, &c1, &c2, &c3);
	if (g_config.rand_type != RAND_PARAM && !test_ctx->setup.key_from) {
		pbk.data = (void *)test_ctx->setup.pub_key;
		pbk.dsize = test_ctx->setup.pub_key_size;
		prk.data = (void *)test_ctx->setup.priv_key;
		prk.dsize = test_ctx->setup.priv_key_size;
		md_ctx = ecc_create_openssl_handle(&prk, &pbk);
		if (!md_ctx)
			return -1;
		pctx = EVP_MD_CTX_pkey_ctx(md_ctx);
		EVP_PKEY_decrypt_init(pctx);
		EVP_PKEY_CTX_ctrl(pctx, -1, -1, EVP_PKEY_CTRL_MD, -1, (void *)get_digest_handle());

		/* openssl check */
		crypto_bin_to_hpre_bin(c1->x.data, c1->x.data, c1->x.bsize, c1->x.dsize);
		crypto_bin_to_hpre_bin(c1->y.data, c1->y.data, c1->y.bsize, c1->y.dsize);
		evp_len = sm2_enc_in_bin_to_evp(buf, c1->x.data, c2->dsize, 32, c3->dsize);
		ret = EVP_PKEY_decrypt(pctx, (void *)ptext, &lens, (void *)buf, evp_len);
		if (ret != 1) {
			HPRE_TST_PRT("EVP_PKEY_decrypt failed, ret = %d\n", ret);
			return -1;
		}

		ecc_del_openssl_handle(md_ctx);

		if (lens != test_ctx->setup.msg_size ||
			memcmp(test_ctx->setup.msg, ptext, lens)){
			HPRE_TST_PRT("openssl decrypt mismatch\n");
			print_data(ptext, lens, "openssl dec out");
			return -1;
		}
	} else {
		memcpy(buf, c1->x.data, c1->x.dsize);
		crypto_bin_to_hpre_bin(buf, c1->x.data, c1->x.bsize, c1->x.dsize);
		memcpy(buf + 32, c1->y.data, c1->y.dsize);
		crypto_bin_to_hpre_bin(buf + 32, c1->y.data, c1->y.bsize, c1->y.dsize);
		memcpy(buf + 32 * 2, c3->data, c3->dsize);
		memcpy(buf + 32 * 2 + c3->dsize, c2->data, c2->dsize);
		lens = 32 * 2 + c2->dsize + c3->dsize;
		if (lens != test_ctx->cp_enc_size ||
			memcmp(test_ctx->cp_enc, buf, test_ctx->cp_enc_size)){
			HPRE_TST_PRT("sm2 op %d mismatch\n", test_ctx->setup.op_type);
			print_data(c1->x.data, c1->x.dsize, "c1 x");
			print_data(c1->y.data, c1->y.dsize, "c1 y");
			print_data(c3->data, c3->dsize, "c3");
			print_data(c2->data, c2->dsize, "c2");
			print_data(buf, lens, "hpre out");
			print_data(test_ctx->cp_enc, test_ctx->cp_enc_size, "openssl out");
			return -1;
		}
	}

	free(buf);
	free(ptext);

	return 0;
}

static int sm2_dec_result_check(struct ecc_test_ctx *test_ctx, __u8 is_async)
{
	struct wd_ecc_req *req = test_ctx->req;
	struct wd_dtb *m = NULL;

	wd_sm2_get_dec_out_params(req->dst, &m);

	if (m->dsize != test_ctx->cp_enc_size ||
		memcmp(test_ctx->cp_enc, m->data, m->dsize)){
		HPRE_TST_PRT("sm2 op %d mismatch\n", test_ctx->setup.op_type);
		print_data(m->data, m->dsize, "hpre out");
		print_data((void *)test_ctx->cp_enc,
			test_ctx->cp_enc_size, "openssl out");
		return -1;
	}

	return 0;
}

static int sm2_kg_result_check(struct ecc_test_ctx *test_ctx, __u8 is_async)
{
	struct ecc_test_ctx_setup *setup = &test_ctx->setup;
	EVP_MD_CTX *md_ctx;
	struct wd_ecc_req *req = test_ctx->req;
	struct wd_dtb *privkey = NULL;
	struct wd_ecc_point *pubkey = NULL;
	struct wd_dtb pbk, prk;
	EVP_PKEY_CTX *pctx;
	char buff[100] = {0x4};
	size_t sig_len = 100;
	int ret;

	wd_sm2_get_kg_out_params(req->dst, &privkey, &pubkey);

	crypto_bin_to_hpre_bin(pubkey->x.data, pubkey->x.data,
		pubkey->x.bsize, pubkey->x.dsize);
	crypto_bin_to_hpre_bin(pubkey->y.data, pubkey->y.data,
		pubkey->y.bsize, pubkey->y.dsize);
	memcpy(&buff[1], pubkey->x.data, 64);
	pbk.data = buff;
	pbk.dsize = 65;
	prk.data = privkey->data;
	prk.dsize = privkey->dsize;

	md_ctx = ecc_create_openssl_handle(&prk, &pbk);
	if (!md_ctx)
		return -1;
	pctx = EVP_MD_CTX_pkey_ctx(md_ctx);
	ret = EVP_PKEY_sign_init(pctx);
	if (ret != 1) {
		HPRE_TST_PRT("EVP_PKEY_sign_init failed, ret = %d\n", ret);
		ret = -1;
		goto del_openssl_handle;
	}

	ret = EVP_PKEY_sign(pctx, (void *)buff, &sig_len, setup->msg,
		(size_t)setup->msg_size);
	if (ret != 1) {
		HPRE_TST_PRT("EVP_PKEY_sign failed, ret = %d\n", ret);
		ret = -1;
		goto del_openssl_handle;
	}

	ret = EVP_PKEY_verify_init(pctx);
	if (ret != 1) {
		HPRE_TST_PRT("EVP_PKEY_verify_init failed, ret = %d\n", ret);
		ret = -1;
		goto del_openssl_handle;
	}

	ret = EVP_PKEY_verify(pctx, (void *)buff, sig_len, (void *)setup->msg,
		(size_t)setup->msg_size);
	if (ret != 1) {
		HPRE_TST_PRT("EVP_PKEY_verify failed, ret = %d\n", ret);
		ret = -1;
		goto del_openssl_handle;
	}

	ret = 0;

del_openssl_handle:
	ecc_del_openssl_handle(md_ctx);

	return ret;
}

static int ecxdh_result_check(struct ecc_test_ctx *test_ctx, __u8 is_async)
{
	struct wd_ecc_req *req = test_ctx->req;
	unsigned char *cp_key;
	u32 cp_size;
	u32 key_size = (wd_ecc_get_key_bits(test_ctx->setup.sess) + 7) / 8;
	void *o_buf;
	int ret;
	struct wd_ecc_point *key = NULL;
	BIGNUM *tmp;
	__u32 out_sz;

	if (test_ctx->setup.op_type == ECDH_HW_GENERATE) {
		cp_key = test_ctx->cp_pub_key;
		cp_size = test_ctx->cp_pub_key_size;
	} else {
		cp_key = test_ctx->cp_share_key;
		cp_size = test_ctx->cp_share_key_size;
	}

	wd_ecxdh_get_out_params(req->dst, &key);
	if (test_ctx->is_x25519_x448)
		o_buf = malloc(key_size);
	else
		o_buf = malloc(key_size * 2);

	if (!o_buf) {
		HPRE_TST_PRT("malloc fail!\n");
		return -1;
	}

	if (test_ctx->setup.op_type == ECDH_HW_GENERATE) {
		if (test_ctx->is_x25519_x448) {
			ret = ecc_point1buf(key, key_size, o_buf, key_size);
			if (ret < 0) {
				HPRE_TST_PRT("ecc_point1buf fail!\n");
				free(o_buf);
				return -1;
			}
		} else {
			ret = ecc_point2buf(key, key_size, o_buf, key_size * 2);
			if (ret < 0) {
				HPRE_TST_PRT("ecc_point2buf fail!\n");
				free(o_buf);
				return -1;
			}
		}
		out_sz = ret;
		tmp = BN_bin2bn(cp_key, key_size, NULL);
		ret = BN_bn2bin(tmp, cp_key);
		cp_size = ret;
		BN_free(tmp);
		if (!test_ctx->is_x25519_x448) {
			tmp = BN_bin2bn(cp_key + key_size, key_size, NULL);
			ret = BN_bn2bin(tmp, cp_key + ret);
			cp_size += ret;
			BN_free(tmp);
		}

	} else {
		ret = key->x.dsize;
		out_sz = ret;
		memcpy(o_buf, key->x.data, ret);
		tmp = BN_bin2bn(cp_key, key_size, NULL);
		ret = BN_bn2bin(tmp, cp_key);
		cp_size = ret;
		BN_free(tmp);
	}

	if (out_sz != cp_size || memcmp(cp_key, o_buf, cp_size)) {
		HPRE_TST_PRT("ecdh op %d mismatch!\n", test_ctx->setup.op_type);

//#ifdef DEBUG
		struct wd_ecc_key *ecc_key;
		struct wd_dtb *p = NULL;

		ecc_key = wd_ecc_get_key(test_ctx->setup.sess);
		wd_ecc_get_prikey_params(ecc_key, &p, NULL, NULL, NULL, NULL, NULL);

		print_data(p->data, ECC_PRIKEY_SZ(p->bsize), "prikey");
		if (test_ctx->setup.op_type == ECDH_HW_GENERATE)
			print_data(test_ctx->cp_pub_key, test_ctx->cp_pub_key_size, "cp_pub_key");
		else
			print_data(test_ctx->cp_share_key, test_ctx->cp_share_key_size, "cp_share_key");
		print_data(o_buf, out_sz, "hpre out");
		print_data(cp_key, cp_size, "openssl out");
//#endif
		free(o_buf);
		return -1;
	}
	free(o_buf);

	return 0;
}

static int ecc_result_check(struct ecc_test_ctx *test_ctx, __u8 is_async)
{
	struct wd_ecc_req *req = test_ctx->req;
	int ret = 0;

	if (!g_config.check)
		return 0;

	if (test_ctx->setup.op_type == ECDH_HW_GENERATE ||
		test_ctx->setup.op_type == ECDH_HW_COMPUTE) {
		ret = ecxdh_result_check(test_ctx, is_async);
	} else if (test_ctx->setup.op_type == ECC_HW_SIGN || test_ctx->setup.op_type == SM2_HW_VERF) {
		ret = ecdsa_sign_result_check(test_ctx, is_async);
	} else if (test_ctx->setup.op_type == ECC_HW_VERF) {
		if (req->status != 0) {
			HPRE_TST_PRT("hpre verf faild = %d!\n", req->status);
			return -1;
		}
	} else if (test_ctx->setup.op_type == SM2_HW_SIGN) {
		ret = sm2_sign_result_check(test_ctx, is_async);
	} else if (test_ctx->setup.op_type == SM2_HW_ENC) {
		ret = sm2_enc_result_check(test_ctx, is_async);
	} else if (test_ctx->setup.op_type == SM2_HW_DEC) {
		ret = sm2_dec_result_check(test_ctx, is_async);
	} else if (test_ctx->setup.op_type == SM2_HW_KG) {
		ret = sm2_kg_result_check(test_ctx, is_async);
	} else {}

	return ret;
}

static void _ecc_perf_cb(void *req_t)
{
	struct wd_ecc_req *req = req_t;
	struct dh_user_tag_info* pSwData = (struct dh_user_tag_info*)req->cb_param;
	struct test_hpre_pthread_dt *thread_data = pSwData->thread_data;
	struct ecc_test_ctx *test_ctx = pSwData->test_ctx;

	thread_data->recv_task_num++;
	ecc_del_test_ctx(test_ctx);
	free(pSwData);
}

static void _ecc_cb(void *req_t)
{
	struct wd_ecc_req *req = req_t;
	struct dh_user_tag_info* pSwData = (struct dh_user_tag_info*)req->cb_param;
	struct timeval start_tval, end_tval;
	int pid, threadId;
	float time, speed;
	int ret;
	static int failTimes = 0;
	struct ecc_test_ctx *test_ctx = pSwData->test_ctx;
	struct test_hpre_pthread_dt *thread_data = pSwData->thread_data;

	start_tval = thread_data->start_tval;
	pid = pSwData->pid;
	threadId = pSwData->thread_id;

	thread_data->recv_task_num++;

	if (req->status != WD_SUCCESS) {
		HPRE_TST_PRT("Proc-%d, %d-TD %s %dtimes fail!, status 0x%02x\n",
			pid, threadId, ecc_op_str[test_ctx->setup.op_type],
			thread_data->send_task_num, req->status);
		goto err;
	}

	if (g_config.check) {
		ret = ecc_result_check(test_ctx, 1);
		if (ret) {
			failTimes++;
			HPRE_TST_PRT("TD-%d:%s result mismatching!\n",
				threadId, ecc_op_str[test_ctx->setup.op_type]);
		}
	}

	gettimeofday(&end_tval, NULL);
	if (is_allow_print(thread_data->send_task_num, DH_ASYNC_GEN, 1)) {
		time = (end_tval.tv_sec - start_tval.tv_sec) * 1000000 +
					(end_tval.tv_usec - start_tval.tv_usec);
		speed = 1 / (time / thread_data->send_task_num) * 1000 * 1000;
		HPRE_TST_PRT("Proc-%d, %d-TD %s %dtimes,%f us, %0.3fps, fail %dtimes(all TD)\n",
				pid, threadId, ecc_op_str[test_ctx->setup.op_type],
				thread_data->send_task_num, time, speed, failTimes);
	}

err:
	ecc_del_test_ctx(test_ctx);
	if (pSwData)
		free(pSwData);
}

void fill_ecc_param_of_curve(struct wd_ecc_curve *param)
{
	__u32 key_bits = g_config.key_bits;
	__u32 key_size = (key_bits + 7) / 8;

	if (g_config.key_bits == 128) {
		param->a.data = ecdh_a_secp128r1;
		param->b.data = ecdh_b_secp128r1;
		param->p.data = ecdh_p_secp128r1;
		param->n.data = ecdh_n_secp128r1;
		param->g.x.data = ecdh_g_secp128r1;
		param->g.y.data = ecdh_g_secp128r1 + key_size;
	} else if (key_bits == 192) {
		param->a.data = ecdh_a_secp192k1;
		param->b.data = ecdh_b_secp192k1;
		param->p.data = ecdh_p_secp192k1;
		param->n.data = ecdh_n_secp192k1;
		param->g.x.data = ecdh_g_secp192k1;
		param->g.y.data = ecdh_g_secp192k1 + key_size;
	} else if (g_config.key_bits == 224) {
		param->a.data = ecdh_a_secp224r1;
		param->b.data = ecdh_b_secp224r1;
		param->p.data = ecdh_p_secp224r1;
		param->n.data = ecdh_n_secp224r1;
		param->g.x.data = ecdh_g_secp224r1;
		param->g.y.data = ecdh_g_secp224r1 + key_size;
	} else if (key_bits == 256) {
		param->a.data = ecdh_a_secp256k1;
		param->b.data = ecdh_b_secp256k1;
		param->p.data = ecdh_p_secp256k1;
		param->n.data = ecdh_n_secp256k1;
		param->g.x.data = ecdh_g_secp256k1;
		param->g.y.data = ecdh_g_secp256k1 + key_size;
	} else if (key_bits == 320) {
		param->a.data = ecdh_a_secp320k1;
		param->b.data = ecdh_b_secp320k1;
		param->p.data = ecdh_p_secp320k1;
		param->n.data = ecdh_n_secp320k1;
		param->g.x.data = ecdh_g_secp320k1;
		param->g.y.data = ecdh_g_secp320k1 + key_size;
	} else if (g_config.key_bits == 384) {
		param->a.data = ecdh_a_secp384r1;
		param->b.data = ecdh_b_secp384r1;
		param->p.data = ecdh_p_secp384r1;
		param->n.data = ecdh_n_secp384r1;
		param->g.x.data = ecdh_g_secp384r1;
		param->g.y.data = ecdh_g_secp384r1 + key_size;
	} else if (key_bits == 521) {
		param->a.data = ecdh_a_secp521r1;
		param->b.data = ecdh_b_secp521r1;
		param->p.data = ecdh_p_secp521r1;
		param->n.data = ecdh_n_secp521r1;
		param->g.x.data = ecdh_g_secp521r1;
		param->g.y.data = ecdh_g_secp521r1 + key_size;
	} else {
		HPRE_TST_PRT("key_bits %d not find\n", key_bits);
		return;
	}

	param->a.bsize = key_size;
	param->a.dsize = key_size;
	param->b.bsize = key_size;
	param->b.dsize = key_size;
	param->p.bsize = key_size;
	param->p.dsize = key_size;
	param->n.bsize = key_size;
	param->n.dsize = key_size;
	param->g.x.bsize = key_size;
	param->g.x.dsize = key_size;
	param->g.y.bsize = key_size;
	param->g.y.dsize = key_size;
}

static void *_ecc_sys_test_thread(void *data)
{
	struct test_hpre_pthread_dt *pdata = data;
	struct dh_user_tag_info *pTag = NULL;
	struct ecc_test_ctx *test_ctx;
	struct ecc_test_ctx_setup setup;
	struct timeval cur_tval;
	enum alg_op_type opType;
	float time_used, speed = 0.0;
	int thread_num;
	cpu_set_t mask;
	int pid = getpid();
	int thread_id = (int)syscall(__NR_gettid);
	int ret, cpuid;
	handle_t sess = 0llu;
	struct wd_ecc_sess_setup sess_setup;
	struct wd_ecc_curve param;
	struct wd_dtb prk, pbk_1;
	struct wd_ecc_point pbk;
	struct wd_ecc_req *req;
	u32 key_size = (g_config.key_bits + 7) >> 3;

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	opType = pdata->op_type;
	thread_num = pdata->thread_num;

	memset(&setup, 0, sizeof(setup));
	if (g_config.perf_test && (!g_config.times && !g_config.seconds)) {
		HPRE_TST_PRT("g_config.times or  g_config.seconds err\n");
		return NULL;
	}

	CPU_SET(cpuid, &mask);
	if (cpuid) {
		ret = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);
		if (ret < 0) {
			HPRE_TST_PRT("Proc-%d, thrd-%d:set affinity fail!\n",
						 pid, thread_id);
			return NULL;
		}
		HPRE_TST_PRT("Proc-%d, thrd-%d bind to cpu-%d!\n",
					 pid, thread_id, cpuid);
	}

	if (strcmp(g_config.curve, "") && !(!strncmp(g_config.op, "x448", 4) || !strncmp(g_config.op, "x25519", 5))) {
		ret = get_ecc_nid(g_config.curve, &setup.nid, &setup.curve_id);
		if (ret < 0) {
			HPRE_TST_PRT("ecc sys test not find curve!\n");
			return NULL;
		}
	}

	if (!g_config.soft_test) {
		memset(&sess_setup, 0, sizeof(sess_setup));
		if (!(!strncmp(g_config.op, "x448", 4) ||
			!strncmp(g_config.op, "x25519", 5) ||
			!strncmp(g_config.op, "sm2", 3))) {
			if (!strcmp(g_config.curve, "")) {
				sess_setup.cv.type = WD_CV_CFG_PARAM;
				fill_ecc_param_of_curve(&param);
				sess_setup.cv.cfg.pparam = &param;
			} else {
				sess_setup.cv.type = WD_CV_CFG_ID;
				sess_setup.cv.cfg.id = setup.curve_id;
			}
		}

		sess_setup.key_bits = g_config.key_bits;

		if (g_config.rand_type == RAND_CB)
			sess_setup.rand.cb = hpre_get_rand;
		if (!strncmp(g_config.op, "sm2", 3))
			sess_setup.alg = "sm2";
		else if (!strncmp(g_config.op, "ecdh", 4))
			sess_setup.alg = "ecdh";
		else if (!strncmp(g_config.op, "ecdsa", 5))
			sess_setup.alg = "ecdsa";

		if (g_config.hash_type != HASH_NON) {
			sess_setup.hash.cb = hpre_compute_hash;
			if (g_config.hash_type == HASH_SHA1)
				sess_setup.hash.type = WD_HASH_SHA1;
			else if (g_config.hash_type == HASH_SHA224)
				sess_setup.hash.type = WD_HASH_SHA224;
			else if (g_config.hash_type == HASH_SHA256)
				sess_setup.hash.type = WD_HASH_SHA256;
			else if (g_config.hash_type == HASH_SHA384)
				sess_setup.hash.type = WD_HASH_SHA384;
			else if (g_config.hash_type == HASH_SHA512)
				sess_setup.hash.type = WD_HASH_SHA512;
			else if (g_config.hash_type == HASH_MD4)
				sess_setup.hash.type = WD_HASH_MD4;
			else if (g_config.hash_type == HASH_MD5)
				sess_setup.hash.type = WD_HASH_MD5;
			else
				sess_setup.hash.type = WD_HASH_SM3;
		}
	}

//	if ((!strncmp(g_config.op, "x25519", 6)) || (!strncmp(g_config.op, "x448", 4))) {
//		if (x_dh_init_test_ctx_setup(&setup, opType)) {
//			return NULL;
//		}
//	} else if (ecc_init_test_ctx_setup(&setup, opType)) {
//		return NULL;
//	}

	if (ecc_init_test_ctx_setup(&setup, opType))
		return NULL;

	if (opType == ECDSA_SIGN || opType == ECDSA_ASYNC_SIGN)
		setup.op_type = (g_config.soft_test) ? ECC_SW_SIGN: ECC_HW_SIGN;
	else if (opType == ECDSA_VERF || opType == ECDSA_ASYNC_VERF)
		setup.op_type = (g_config.soft_test) ? ECC_SW_VERF: ECC_HW_VERF;
	else if (opType == SM2_SIGN || opType == SM2_ASYNC_SIGN)
		setup.op_type = (g_config.soft_test) ? SM2_SW_SIGN: SM2_HW_SIGN;
	else if (opType == SM2_VERF || opType == SM2_ASYNC_VERF)
		setup.op_type = (g_config.soft_test) ? SM2_SW_VERF: SM2_HW_VERF;
	else if (opType == SM2_ENC || opType == SM2_ASYNC_ENC)
		setup.op_type = (g_config.soft_test) ? SM2_SW_ENC: SM2_HW_ENC;
	else if (opType == SM2_DEC|| opType == SM2_ASYNC_DEC)
		setup.op_type = (g_config.soft_test) ? SM2_SW_DEC: SM2_HW_DEC;
	else if (opType == SM2_KG|| opType == SM2_ASYNC_KG)
		setup.op_type = (g_config.soft_test) ? SM2_SW_KG: SM2_HW_KG;
	else if (opType == ECDH_ASYNC_GEN || opType == ECDH_GEN ||
		 opType == X25519_ASYNC_GEN || opType == X25519_GEN ||
		 opType == X448_ASYNC_GEN || opType == X448_GEN)
		setup.op_type = (g_config.soft_test) ? ECDH_SW_GENERATE: ECDH_HW_GENERATE;
	else if (opType == ECDH_ASYNC_COMPUTE || opType == ECDH_COMPUTE ||
		 opType == X25519_ASYNC_COMPUTE || opType == X25519_COMPUTE ||
		 opType == X448_ASYNC_COMPUTE || opType == X448_COMPUTE)
		setup.op_type = (g_config.soft_test) ? ECDH_SW_COMPUTE: ECDH_HW_COMPUTE;

new_test_again:

	if (!g_config.soft_test) {
		sess = wd_ecc_alloc_sess(&sess_setup);
		if (!sess) {
			HPRE_TST_PRT("wd_ecc_alloc_sess failed\n");
			return NULL;
		}

		prk.data = (void *)setup.priv_key;
		prk.dsize = setup.priv_key_size;
		prk.bsize = setup.priv_key_size;
		pbk.x.data = (char *)setup.pub_key + 1;
		pbk.x.dsize = key_size;
		pbk.x.bsize = key_size;
		pbk.y.data = pbk.x.data + key_size;
		pbk.y.dsize = key_size;
		pbk.y.bsize = key_size;
		ret = set_sess_key(sess, &prk, &pbk);
		if (ret) {
			wd_ecc_free_sess(sess);
			return NULL;
		}
		setup.sess = sess;

		if (!g_config.perf_test && !strncmp(g_config.op, "sm2", 3)) {
			pbk_1.data = (void *)setup.pub_key;
			pbk_1.dsize = setup.pub_key_size;
			prk.data = (void *)setup.priv_key;
			prk.dsize = setup.priv_key_size;
			setup.openssl_handle = ecc_create_openssl_handle(&prk, &pbk_1);
			if (!setup.openssl_handle) {
				wd_ecc_free_sess(sess);
				return NULL;
			}
		}

	}

new_test_with_no_req_ctx: // async test

	test_ctx = ecc_create_test_ctx(setup, opType);
	if (!test_ctx) {
		HPRE_TST_PRT("ecc_create_test_ctx failed\n");
		return NULL;
	}
	if (opType >= X25519_GEN && opType <= X448_ASYNC_COMPUTE)
		test_ctx->is_x25519_x448 = 1;

	req = test_ctx->req;
	do {
		if (is_async_test(opType)) {
			pTag = malloc(sizeof(struct dh_user_tag_info));
			if (!pTag) {
				HPRE_TST_PRT("malloc pTag fail!\n");
				ret = -1;
				goto fail_release;
			}

			pTag->test_ctx = test_ctx;
			pTag->thread_data = pdata;
			pTag->pid = pid;
			pTag->thread_id = thread_id;
			req->cb_param = pTag;
			if (g_config.perf_test)
				req->cb = _ecc_perf_cb;
			else
				req->cb = _ecc_cb;
		}

		if (opType == ECDSA_ASYNC_SIGN || opType == ECDSA_SIGN) {
			if (ecdsa_sign(test_ctx, pTag)) { // todo
				ret = -1;
				goto fail_release;
			}
		} else if (opType == SM2_SIGN || opType == SM2_ASYNC_SIGN) {
			if (sm2_sign(test_ctx, pTag)) {
				ret = -1;
				goto fail_release;
			}
		} else if (opType == ECDSA_VERF || opType == ECDSA_ASYNC_VERF) {
			if (ecdsa_verf(test_ctx, pTag)) { // todo
				ret = -1;
				goto fail_release;
			}
		} else if (opType == SM2_VERF || opType == SM2_ASYNC_VERF) {
			if (sm2_verf(test_ctx, pTag)) {
				ret = -1;
				goto fail_release;
			}
		} else if (opType == SM2_ENC || opType == SM2_ASYNC_ENC) {
			if (sm2_enc(test_ctx, pTag)) {
				ret = -1;
				goto fail_release;
			}
		} else if (opType == SM2_DEC || opType == SM2_ASYNC_DEC) {
			if (sm2_dec(test_ctx, pTag)) {
				ret = -1;
				goto fail_release;
			}
		} else if (opType == SM2_KG || opType == SM2_ASYNC_KG) {
			if (sm2_kg(test_ctx, pTag)) {
				ret = -1;
				goto fail_release;
			}
		} else if (opType == ECDH_ASYNC_GEN || opType == ECDH_GEN ||
			   opType == X25519_ASYNC_GEN || opType == X25519_GEN ||
			   opType == X448_ASYNC_GEN || opType == X448_GEN) {
			if (ecxdh_generate_key(test_ctx, pTag)) {
				ret = -1;
				goto fail_release;
			}
		} else if (opType == ECDH_ASYNC_COMPUTE || opType == ECDH_COMPUTE ||
			   opType == X25519_ASYNC_COMPUTE || opType == X25519_COMPUTE ||
			   opType == X448_ASYNC_COMPUTE || opType == X448_COMPUTE) {
			if (ecxdh_compute_key(test_ctx, pTag)) {
				ret = -1;
				goto fail_release;
			}
		}

		pdata->send_task_num++;
		if (!is_async_test(opType)) {

			if (g_config.soft_test && !g_config.perf_test) {
				ecc_del_test_ctx(test_ctx);
				goto new_test_with_no_req_ctx;
			} else if (!g_config.perf_test) {
				if (ecc_result_check(test_ctx, 0)) {
					ret = -1;
					goto fail_release;
				}

				if (is_allow_print(pdata->send_task_num, opType, thread_num)) {
					HPRE_TST_PRT("Proc-%d, %d-TD: %s %uth succ!\n",
						getpid(), (int)syscall(__NR_gettid),
						ecc_op_str[test_ctx->setup.op_type], pdata->send_task_num);
				}


				if (!strncmp(g_config.op, "sm2", 3)) {
					ecc_del_openssl_handle(test_ctx->setup.openssl_handle);
					test_ctx->setup.openssl_handle = NULL;
				}

				wd_ecc_free_sess(sess);
				ecc_del_test_ctx(test_ctx);
				sess = 0;
				test_ctx = NULL;

				if (is_exit(pdata))
					goto func_test_exit;

				goto new_test_again;
			}
		} else {
			if (is_exit(pdata))
				break;

			goto new_test_with_no_req_ctx;
		}
	} while(!is_exit(pdata));

	if (!is_async_test(opType))
		pdata->recv_task_num = pdata->send_task_num;

	if (g_config.perf_test) {
		gettimeofday(&cur_tval, NULL);
		time_used = (float)((cur_tval.tv_sec -pdata->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - pdata->start_tval.tv_usec);

		if (g_config.seconds){
			speed = pdata->recv_task_num / time_used * 1000000;
		} else if (g_config.times) {
			speed = pdata->recv_task_num * 1.0 * 1000 * 1000 / time_used;
		}
		HPRE_TST_PRT("<< Proc-%d, %d-TD: run %s %s mode %u key_bits at %0.3f ops!\n",
			pid, thread_id, g_config.op, g_config.alg_mode, g_config.key_bits, speed);
		pdata->perf = speed;
	}

	/* wait for recv finish */
	while (pdata->send_task_num != pdata->recv_task_num) {
		usleep(1000 * 1000);
		if (g_config.with_log)
			HPRE_TST_PRT("<< Proc-%d, %d-TD: total send %u: recv %u, wait recv finish...!\n",
				pid, thread_id, pdata->send_task_num, pdata->recv_task_num);
	}

	ret = 0;

fail_release:

	if (!g_config.soft_test && !is_async_test(opType))
		wd_ecc_free_sess(test_ctx->setup.sess);

	if (!is_async_test(opType))
		ecc_del_test_ctx(test_ctx);

	return NULL;

func_test_exit:

	return NULL;
}

static inline int _get_cpu_id(int thr, __u64 core_mask)
{
	__u64 i;
	int cnt = 0;


	for (i = 1; i < 64; i++) {
		if (core_mask & (0x1ull << i)) {
			if (thr == cnt)
				return i;
			cnt++;
		}
	}

	return 0;
}

static inline int _get_one_bits(__u64 val)
{
	int count = 0;

	while (val) {
		if (val % 2 == 1)
			count++;
		val = val / 2;
	}

	return count;
}

int hpre_test_write_to_file(__u8 *out, int size, char *out_file,
							int handle, int try_close)
{
	int fd = -1, bytes_write;

	if (!out || !size || !out_file) {
		HPRE_TST_PRT("para err while try to write file!\n");
		return -EINVAL;
	}

	if (handle < 0) {
		fd = open(out_file, O_WRONLY | O_CREAT,
				  S_IRUSR | S_IWUSR);
		if (fd < 0) {
			HPRE_TST_PRT("create %s file fail!\n", out_file);
			return fd;
		}
	} else
		fd = handle;

	bytes_write = write(fd, out, size);
	if (bytes_write < 0 || bytes_write < size) {
		if (try_close)
			close(fd);
		HPRE_TST_PRT("write data to %s file fail!\n", out_file);
		return -ENOMEM;
	}
	if (try_close)
		close(fd);

	/* to be fixed */
	return fd;
}

#ifndef HAVE_CRYPTO
static int get_rsa_key_from_test_sample(handle_t sess, char *pubkey_file,
			char *privkey_file,
			char *crt_privkey_file, int is_file)
{
	int ret = -1, bits;
	const __u8 *p, *q, *n, *e, *d, *dmp1, *dmq1, *iqmp;
	struct wd_dtb wd_e, wd_d, wd_n, wd_dq, wd_dp, wd_qinv, wd_q, wd_p;
	u32 key_size = g_config.key_bits >> 3;
	__u32 key_bits = g_config.key_bits;

	memset(&wd_e, 0, sizeof(wd_e));
	memset(&wd_d, 0, sizeof(wd_d));
	memset(&wd_n, 0, sizeof(wd_n));
	memset(&wd_dq, 0, sizeof(wd_dq));
	memset(&wd_dp, 0, sizeof(wd_dp));
	memset(&wd_qinv, 0, sizeof(wd_qinv));
	memset(&wd_q, 0, sizeof(wd_q));
	memset(&wd_p, 0, sizeof(wd_p));

	bits = wd_rsa_get_key_bits(sess);
	if (bits == 1024) {
		e = rsa_e_1024;
		p = rsa_p_1024;
		q = rsa_q_1024;
		dmp1 = rsa_dp_1024;
		dmq1 = rsa_dq_1024;
		iqmp = rsa_qinv_1024;
		d = rsa_d_1024;
		n = rsa_n_1024;
	} else if (bits == 2048) {
		e = rsa_e_2048;
		p = rsa_p_2048;
		q = rsa_q_2048;
		dmp1 = rsa_dp_2048;
		dmq1 = rsa_dq_2048;
		iqmp = rsa_qinv_2048;
		d = rsa_d_2048;
		n = rsa_n_2048;
	} else if (bits == 3072) {
		e = rsa_e_3072;
		p = rsa_p_3072;
		q = rsa_q_3072;
		dmp1 = rsa_dp_3072;
		dmq1 = rsa_dq_3072;
		iqmp = rsa_qinv_3072;
		d = rsa_d_3072;
		n = rsa_n_3072;
	} else if (bits == 4096) {
		e = rsa_e_4096;
		p = rsa_p_4096;
		q = rsa_q_4096;
		dmp1 = rsa_dp_4096;
		dmq1 = rsa_dq_4096;
		iqmp = rsa_qinv_4096;
		d = rsa_d_4096;
		n = rsa_n_4096;
	} else {
		HPRE_TST_PRT("invalid key bits = %d!\n", bits);
		return -1;
	}

	wd_e.bsize = key_size;
	wd_e.data = malloc(GEN_PARAMS_SZ(key_size));
	wd_n.bsize = wd_e.bsize;
	wd_n.data = wd_e.data + wd_e.bsize;

	memcpy(wd_e.data, e, key_size);
	wd_e.dsize = key_size;
	memcpy(wd_n.data, n, key_size);
	wd_n.dsize = key_size;
	if (wd_rsa_set_pubkey_params(sess, &wd_e, &wd_n))
	{
		HPRE_TST_PRT("set rsa pubkey failed %d!\n", ret);
		goto gen_fail;
	}

	if (pubkey_file && is_file) {
		ret = hpre_test_write_to_file((unsigned char *)wd_e.data, g_config.key_bits >> 2,
					  pubkey_file, -1, 1);
		if (ret < 0)
			goto gen_fail;
		HPRE_TST_PRT("RSA public key was written to %s!\n",
					 privkey_file);
	}

	if (rsa_key_in) {
		memset(rsa_key_in->e, 0, key_size);
		memset(rsa_key_in->p, 0, key_size >> 1);
		memset(rsa_key_in->q, 0, key_size >> 1);
		memcpy(rsa_key_in->e, e, key_size);
		rsa_key_in->e_size = key_size;
		rsa_key_in->p_size = key_size / 2;
		rsa_key_in->q_size = key_size / 2;
		memcpy(rsa_key_in->p, p, key_size / 2);
		memcpy(rsa_key_in->q, q, key_size / 2);
	}

	if (wd_rsa_is_crt(sess)) {
		wd_dq.bsize = CRT_PARAM_SZ(key_size);
		wd_dq.data = malloc(CRT_PARAMS_SZ(key_size));
		wd_dp.bsize = CRT_PARAM_SZ(key_size);
		wd_dp.data = wd_dq.data + wd_dq.bsize;
		wd_q.bsize = CRT_PARAM_SZ(key_size);
		wd_q.data = wd_dp.data + wd_dp.bsize;
		wd_p.bsize = CRT_PARAM_SZ(key_size);
		wd_p.data = wd_q.data + wd_q.bsize;
		wd_qinv.bsize = CRT_PARAM_SZ(key_size);
		wd_qinv.data = wd_p.data + wd_p.bsize;

		/* CRT mode private key */
		wd_dq.dsize = key_size / 2;
		memcpy(wd_dq.data, dmq1, key_size / 2);

		wd_dp.dsize = key_size / 2;
		memcpy(wd_dp.data, dmp1, key_size / 2);

		wd_q.dsize = key_size / 2;
		memcpy(wd_q.data, q, key_size / 2);

		wd_p.dsize = key_size / 2;
		memcpy(wd_p.data, p, key_size / 2);

		wd_qinv.dsize = key_size / 2;
		memcpy(wd_qinv.data, iqmp, key_size / 2);

		if (wd_rsa_set_crt_prikey_params(sess, &wd_dq,
					&wd_dp, &wd_qinv,
					&wd_q, &wd_p))
		{
			HPRE_TST_PRT("set rsa crt prikey failed %d!\n", ret);
			goto gen_fail;
		}


		if (crt_privkey_file && is_file) {
			ret = hpre_test_write_to_file((unsigned char *)wd_dq.data,
						  (key_bits >> 4) * 5, crt_privkey_file, -1, 0);
			if (ret < 0)
				goto gen_fail;
			ret = hpre_test_write_to_file((unsigned char *)wd_e.data,
						  (key_bits >> 2), crt_privkey_file, ret, 1);
			if (ret < 0)
				goto gen_fail;
			HPRE_TST_PRT("RSA CRT private key was written to %s!\n",
						 crt_privkey_file);
		} else if (crt_privkey_file && !is_file) {
			memcpy(crt_privkey_file, wd_dq.data, (key_bits >> 4) * 5);
			memcpy(crt_privkey_file + (key_bits >> 4) * 5,
				   wd_e.data, (key_bits >> 2));
		}

	} else {
			//wd_rsa_get_prikey_params(prikey, &wd_d, &wd_n);
			wd_d.bsize = key_size;
			wd_d.data = malloc(GEN_PARAMS_SZ(key_size));
			wd_n.bsize = key_size;
			wd_n.data = wd_d.data + wd_d.bsize;

			/* common mode private key */
			wd_d.dsize = key_size;
			memcpy(wd_d.data, d, key_size);
			wd_n.dsize = key_size;
			memcpy(wd_n.data, n, key_size);

			if (wd_rsa_set_prikey_params(sess, &wd_d, &wd_n))
			{
				HPRE_TST_PRT("set rsa prikey failed %d!\n", ret);
				goto gen_fail;
			}


			if (privkey_file && is_file) {
				ret = hpre_test_write_to_file((unsigned char *)wd_d.data,
							  (key_size),
							  privkey_file, -1, 0);
				if (ret < 0)
					goto gen_fail;
				ret = hpre_test_write_to_file((unsigned char *)wd_n.data,
							  (key_size),
							  privkey_file, ret, 1);
				if (ret < 0)
					goto gen_fail;

				ret = hpre_test_write_to_file((unsigned char *)wd_e.data,
							  (key_size), privkey_file, ret, 1);
				if (ret < 0)
					goto gen_fail;
				HPRE_TST_PRT("RSA common private key was written to %s!\n",
							 privkey_file);
			} else if (privkey_file && !is_file) {
				memcpy(privkey_file, wd_d.data, key_size);
				memcpy(privkey_file + key_size, wd_n.data, key_size);
				memcpy(privkey_file + 2 * key_size, wd_e.data, key_size);
                                memcpy(privkey_file + 3 * key_size, wd_n.data, key_size);
			}
	}

	if (wd_e.data)
		free(wd_e.data);

	if (wd_rsa_is_crt(sess)) {
		if (wd_dq.data)
			free(wd_dq.data);
	} else {
		if (wd_d.data)
			free(wd_d.data);
	}

	return 0;
gen_fail:

	if (wd_e.data)
		free(wd_e.data);

	if (wd_rsa_is_crt(sess)) {
		if (wd_dq.data)
			free(wd_dq.data);
	} else {
		if (wd_d.data)
			free(wd_d.data);
	}

	return ret;
}

#else

static int test_rsa_key_gen(handle_t sess, char *pubkey_file,
			char *privkey_file,
			char *crt_privkey_file, int is_file)

{
		int ret;
		EVP_PKEY *test_rsa = NULL;
		EVP_PKEY_CTX *genctx = NULL;
		BIGNUM *p, *q, *n, *e, *d, *dmp1, *dmq1, *iqmp;
		BIGNUM *e_value = NULL;
		//struct wd_dtb *wd_e, *wd_d, *wd_n, *wd_dq, *wd_dp, *wd_qinv, *wd_q, *wd_p;
		struct wd_dtb wd_e, wd_d, wd_n, wd_dq, wd_dp, wd_qinv, wd_q, wd_p;
		//struct wd_rsa_pubkey *pubkey;
		//struct wd_rsa_prikey *prikey;
		u32 key_size = g_config.key_bits >> 3;
		u32 key_bits = g_config.key_bits;
		char *tmp;

		memset(&wd_e, 0, sizeof(wd_e));
		memset(&wd_d, 0, sizeof(wd_d));
		memset(&wd_n, 0, sizeof(wd_n));
		memset(&wd_dq, 0, sizeof(wd_dq));
		memset(&wd_dp, 0, sizeof(wd_dp));
		memset(&wd_qinv, 0, sizeof(wd_qinv));
		memset(&wd_q, 0, sizeof(wd_q));
		memset(&wd_p, 0, sizeof(wd_p));

		genctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
		if (!genctx) {
			HPRE_TST_PRT("EVP_PKEY_CTX_new_from_name fail!\n");
			return -ENOMEM;
		}
		ret = EVP_PKEY_keygen_init(genctx);
		if (ret != 1) {
			HPRE_TST_PRT("EVP_PKEY_keygen_init fail!\n");
			goto gen_fail;
		}
		ret = EVP_PKEY_CTX_set_rsa_keygen_bits(genctx, key_bits);
		if (ret != 1) {
			HPRE_TST_PRT("EVP_PKEY_CTX_set_rsa_keygen_bits fail!\n");
			goto gen_fail;
		}
		ret = EVP_PKEY_keygen(genctx, &test_rsa);
		EVP_PKEY_CTX_free(genctx);
		genctx = NULL;
		if (ret != 1) {
			HPRE_TST_PRT("EVP_PKEY_keygen fail!\n");
			goto gen_fail;
		}

		e_value = BN_new();
		if (!e_value) {
			HPRE_TST_PRT("BN new e fail!\n");
			ret = -ENOMEM;
			goto gen_fail;
		}
		ret = BN_set_word(e_value, 65537);
		if (ret != 1) {
			HPRE_TST_PRT("BN_set_word fail!\n");
			ret = -1;
			goto gen_fail;
		}

		EVP_PKEY_get_bn_param(test_rsa, OSSL_PKEY_PARAM_RSA_N, &n);
		EVP_PKEY_get_bn_param(test_rsa, OSSL_PKEY_PARAM_RSA_E, &e);
		EVP_PKEY_get_bn_param(test_rsa, OSSL_PKEY_PARAM_RSA_D, &d);
		EVP_PKEY_get_bn_param(test_rsa, OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
		EVP_PKEY_get_bn_param(test_rsa, OSSL_PKEY_PARAM_RSA_FACTOR2, &q);
		EVP_PKEY_get_bn_param(test_rsa, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dmp1);
		EVP_PKEY_get_bn_param(test_rsa, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dmq1);
		EVP_PKEY_get_bn_param(test_rsa, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp);

		wd_e.bsize = key_size;
		wd_e.data = malloc(GEN_PARAMS_SZ(key_size));
		wd_n.bsize = wd_e.bsize;
		wd_n.data = wd_e.data + wd_e.bsize;

		wd_e.dsize = BN_bn2bin(e, (unsigned char *)wd_e.data);
		if (wd_e.dsize > wd_e.bsize) {
			HPRE_TST_PRT("e bn to bin overflow!\n");
			goto gen_fail;
		}
		wd_n.dsize = BN_bn2bin(n, (unsigned char *)wd_n.data);
		if (wd_n.dsize > wd_n.bsize) {
			HPRE_TST_PRT("n bn to bin overflow!\n");
			goto gen_fail;
		}

		if (wd_rsa_set_pubkey_params(sess, &wd_e, &wd_n))
		{
			HPRE_TST_PRT("set rsa pubkey failed %d!\n", ret);
			goto gen_fail;
		}

		tmp = malloc(key_size);
		if (!tmp) {
			HPRE_TST_PRT("failed to malloc!\n");
			goto gen_fail;
		}

		memcpy(tmp, wd_e.data, wd_e.dsize);
		crypto_bin_to_hpre_bin(wd_e.data, tmp, wd_e.bsize, wd_e.dsize);
		memcpy(tmp, wd_n.data, wd_n.dsize);
		crypto_bin_to_hpre_bin(wd_n.data, tmp, wd_n.bsize, wd_n.dsize);
		wd_e.dsize = key_size;
		wd_n.dsize = key_size;

		if (pubkey_file && is_file) {
			ret = hpre_test_write_to_file((unsigned char *)wd_e.data, key_bits >> 2,
			pubkey_file, -1, 1);
			if (ret < 0)
				goto gen_fail;
			HPRE_TST_PRT("RSA public key was written to %s!\n",
			privkey_file);
		}

		if (rsa_key_in) {
			memset(rsa_key_in->e, 0, key_size);
			memset(rsa_key_in->p, 0, key_size >> 1);
			memset(rsa_key_in->q, 0, key_size >> 1);
			rsa_key_in->e_size = BN_bn2bin(e, (unsigned char *)rsa_key_in->e);
			rsa_key_in->p_size = BN_bn2bin(p, (unsigned char *)rsa_key_in->p);
			rsa_key_in->q_size = BN_bn2bin(q, (unsigned char *)rsa_key_in->q);
		}

		//wd_rsa_get_prikey(sess, &prikey);
		if (wd_rsa_is_crt(sess)) {
			//wd_rsa_get_crt_prikey_params(prikey, &wd_dq, &wd_dp, &wd_qinv, &wd_q, &wd_p);
			wd_dq.bsize = CRT_PARAM_SZ(key_size);
			wd_dq.data = malloc(CRT_PARAMS_SZ(key_size));
			wd_dp.bsize = CRT_PARAM_SZ(key_size);
			wd_dp.data = wd_dq.data + wd_dq.bsize;
			wd_q.bsize = CRT_PARAM_SZ(key_size);
			wd_q.data = wd_dp.data + wd_dp.bsize;
			wd_p.bsize = CRT_PARAM_SZ(key_size);
			wd_p.data = wd_q.data + wd_q.bsize;
			wd_qinv.bsize = CRT_PARAM_SZ(key_size);
			wd_qinv.data = wd_p.data + wd_p.bsize;

			/* CRT mode private key */
			wd_dq.dsize = BN_bn2bin(dmq1, (unsigned char *)wd_dq.data);
			if (wd_dq.dsize > wd_dq.bsize) {
				HPRE_TST_PRT("dq bn to bin overflow!\n");
				goto gen_fail;
			}

			wd_dp.dsize = BN_bn2bin(dmp1, (unsigned char *)wd_dp.data);
			if (wd_dp.dsize > wd_dp.bsize) {
				HPRE_TST_PRT("dp bn to bin overflow!\n");
				goto gen_fail;
			}

			wd_q.dsize = BN_bn2bin(q, (unsigned char *)wd_q.data);
			if (wd_q.dsize > wd_q.bsize) {
				HPRE_TST_PRT("q bn to bin overflow!\n");
				goto gen_fail;
			}

			wd_p.dsize = BN_bn2bin(p, (unsigned char *)wd_p.data);
			if (wd_p.dsize > wd_p.bsize) {
				HPRE_TST_PRT("p bn to bin overflow!\n");
				goto gen_fail;
			}

			wd_qinv.dsize = BN_bn2bin(iqmp, (unsigned char *)wd_qinv.data);
			if (wd_qinv.dsize > wd_qinv.bsize) {
				HPRE_TST_PRT("qinv bn to bin overflow!\n");
				goto gen_fail;
			}

			if (wd_rsa_set_crt_prikey_params(sess, &wd_dq,
				&wd_dp, &wd_qinv,
				&wd_q, &wd_p))
			{
				HPRE_TST_PRT("set rsa crt prikey failed %d!\n", ret);
				goto gen_fail;
			}

			memcpy(tmp, wd_dq.data, wd_dq.dsize);
			crypto_bin_to_hpre_bin(wd_dq.data, tmp, wd_dq.bsize, wd_dq.dsize);
			memcpy(tmp, wd_dp.data, wd_dp.dsize);
			crypto_bin_to_hpre_bin(wd_dp.data, tmp, wd_dp.bsize, wd_dp.dsize);
			memcpy(tmp, wd_q.data, wd_q.dsize);
			crypto_bin_to_hpre_bin(wd_q.data, tmp, wd_q.bsize, wd_q.dsize);
			memcpy(tmp, wd_p.data, wd_p.dsize);
			crypto_bin_to_hpre_bin(wd_p.data, tmp, wd_p.bsize, wd_p.dsize);
			memcpy(tmp, wd_qinv.data, wd_qinv.dsize);
			crypto_bin_to_hpre_bin(wd_qinv.data, tmp, wd_qinv.bsize, wd_qinv.dsize);
			wd_dq.dsize = key_size / 2;
			wd_dp.dsize = key_size / 2;
			wd_q.dsize = key_size / 2;
			wd_p.dsize = key_size / 2;
			wd_qinv.dsize = key_size / 2;


			if (crt_privkey_file && is_file) {
				ret = hpre_test_write_to_file((unsigned char *)wd_dq.data,
				(key_bits >> 4) * 5, crt_privkey_file, -1, 0);
				if (ret < 0)
					goto gen_fail;
				ret = hpre_test_write_to_file((unsigned char *)wd_e.data,
				(key_bits >> 2), crt_privkey_file, ret, 1);
				if (ret < 0)
					goto gen_fail;
				HPRE_TST_PRT("RSA CRT private key was written to %s!\n",
				crt_privkey_file);
			} else if (crt_privkey_file && !is_file) {
				memcpy(crt_privkey_file, wd_dq.data, (key_bits >> 4) * 5);
				memcpy(crt_privkey_file + (key_bits >> 4) * 5,
				wd_e.data, (key_bits >> 2));
			}

		} else {
			//wd_rsa_get_prikey_params(prikey, &wd_d, &wd_n);
				wd_d.bsize = key_size;
				wd_d.data = malloc(GEN_PARAMS_SZ(key_size));
				wd_n.bsize =key_size;
				wd_n.data = wd_d.data + wd_d.bsize;

				/* common mode private key */
				wd_d.dsize = BN_bn2bin(d, (unsigned char *)wd_d.data);
				wd_n.dsize = BN_bn2bin(n, (unsigned char *)wd_n.data);

				if (wd_rsa_set_prikey_params(sess, &wd_d, &wd_n))
				{
					HPRE_TST_PRT("set rsa prikey failed %d!\n", ret);
					goto gen_fail;
				}

				memcpy(tmp, wd_d.data, wd_d.dsize);
				crypto_bin_to_hpre_bin(wd_d.data, tmp, wd_d.bsize, wd_d.dsize);
				memcpy(tmp, wd_n.data, wd_n.dsize);
				crypto_bin_to_hpre_bin(wd_n.data, tmp, wd_n.bsize, wd_n.dsize);
				wd_d.dsize = key_size;
				wd_n.dsize = key_size;


				if (privkey_file && is_file) {
					ret = hpre_test_write_to_file((unsigned char *)wd_d.data,
					(key_size),
					privkey_file, -1, 0);
					if (ret < 0)
						goto gen_fail;
					ret = hpre_test_write_to_file((unsigned char *)wd_n.data,
					(key_size),
					privkey_file, ret, 1);
					if (ret < 0)
						goto gen_fail;

					ret = hpre_test_write_to_file((unsigned char *)wd_e.data,
					(key_size), privkey_file, ret, 1);
					if (ret < 0)
						goto gen_fail;
					HPRE_TST_PRT("RSA common private key was written to %s!\n",
					privkey_file);
				} else if (privkey_file && !is_file) {
					memcpy(privkey_file, wd_d.data, key_size);
					memcpy(privkey_file + key_size, wd_n.data, key_size);
					memcpy(privkey_file + 2 * key_size, wd_e.data, key_size);
					memcpy(privkey_file + 3 * key_size, wd_n.data, key_size);
				}
		}

		EVP_PKEY_free(test_rsa);
		BN_free(e_value);

		if (wd_e.data)
			free(wd_e.data);

		if (wd_rsa_is_crt(sess)) {
			if (wd_dq.data)
				free(wd_dq.data);
		} else {
			if (wd_d.data)
				free(wd_d.data);
		}

		free(tmp);
		return 0;
		gen_fail:
		EVP_PKEY_free(test_rsa);
		EVP_PKEY_CTX_free(genctx);
		BN_free(e_value);

		if (wd_e.data)
			free(wd_e.data);

		if (wd_rsa_is_crt(sess)) {
			if (wd_dq.data)
				free(wd_dq.data);
		} else {
			if (wd_d.data)
				free(wd_d.data);
		}

		return ret;
}


int hpre_test_fill_keygen_opdata(handle_t sess, struct wd_rsa_req *req)
{
	struct wd_dtb *e, *p, *q;
	struct wd_rsa_pubkey *pubkey;
	struct wd_rsa_prikey *prikey;
	struct wd_dtb t_e, t_p, t_q;

	wd_rsa_get_pubkey(sess, &pubkey);
	wd_rsa_get_pubkey_params(pubkey, &e, NULL);
	wd_rsa_get_prikey(sess, &prikey);

	if (wd_rsa_is_crt(sess)) {
		wd_rsa_get_crt_prikey_params(prikey, NULL , NULL, NULL, &q, &p);
	} else {
		e = &t_e;
		p = &t_p;
		q = &t_q;
		e->data = rsa_key_in->e;
		e->dsize = rsa_key_in->e_size;
		p->data = rsa_key_in->p;
		p->dsize = rsa_key_in->p_size;
		q->data = rsa_key_in->q;
		q->dsize = rsa_key_in->q_size;
	}

	req->src = wd_rsa_new_kg_in(sess, e, p, q);
	if (!req->src) {
		HPRE_TST_PRT("create rsa kgen in fail!\n");
		return -ENOMEM;
	}
	req->dst = wd_rsa_new_kg_out(sess);
	if (!req->dst) {
		HPRE_TST_PRT("create rsa kgen out fail!\n");
		return -ENOMEM;
	}
	return 0;
}

static BIGNUM *hpre_bin_to_bn(void *bin, int raw_size)
{
	if (!bin || !raw_size)
		return NULL;

	return BN_bin2bn((const unsigned char *)bin, raw_size, NULL);
}

int hpre_test_result_check(handle_t sess,  struct wd_rsa_req *req, void *key)
{
	struct wd_rsa_kg_out *out = (void *)req->dst;
	struct wd_rsa_prikey *prikey;
	int ret, keybits, key_size;
	void *ssl_out;
	BIGNUM *nn;
	BIGNUM *e;
	EVP_PKEY *rsa = NULL;
	size_t outlen;

	wd_rsa_get_prikey(sess, &prikey);
	keybits = wd_rsa_get_key_bits(sess);
	key_size = keybits >> 3;
	if (req->op_type == WD_RSA_GENKEY) {
		if (wd_rsa_is_crt(sess)) {
			struct wd_dtb qinv, dq, dp;
			struct wd_dtb *s_qinv, *s_dq, *s_dp;

			wd_rsa_get_crt_prikey_params(prikey, &s_dq, &s_dp,
			&s_qinv, NULL, NULL);
			wd_rsa_get_kg_out_crt_params(out, &qinv, &dq, &dp);

			if (memcmp(s_qinv->data, qinv.data, s_qinv->dsize)) {
				HPRE_TST_PRT("keygen  qinv  mismatch!\n");
				return -EINVAL;
			}
			if (memcmp(s_dq->data, dq.data, s_dq->dsize)) {
				HPRE_TST_PRT("keygen  dq mismatch!\n");
				return -EINVAL;
			}
			if (memcmp(s_dp->data, dp.data, s_dp->dsize)) {
				HPRE_TST_PRT("keygen  dp  mismatch!\n");
				return -EINVAL;
			}
		} else {
			struct wd_dtb d, n;
			struct wd_dtb *s_d, *s_n;

			wd_rsa_get_kg_out_params(out, &d, &n);

			wd_rsa_get_prikey_params(prikey, &s_d, &s_n);

			/* check D */
			if (memcmp(s_n->data, n.data, s_n->dsize)) {
				HPRE_TST_PRT("key generate N result mismatching!\n");
				return -EINVAL;
			}
			if (memcmp(s_d->data, d.data, s_d->dsize)) {
				HPRE_TST_PRT("key generate D result mismatching!\n");
				return -EINVAL;
			}
		}
	} else if (req->op_type == WD_RSA_VERIFY) {
		ssl_out = malloc(key_size);
		if (!ssl_out) {
			HPRE_TST_PRT("malloc ssl out fail!\n");
			return -ENOMEM;
		}
		if (key) {
			OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
			OSSL_PARAM *params;

			nn = hpre_bin_to_bn(key + key_size,
			key_size);
			if (!nn) {
				HPRE_TST_PRT("n bin2bn err!\n");
				return -EINVAL;
			}
			e = hpre_bin_to_bn(key, key_size);
			if (!e) {
				HPRE_TST_PRT("e bin2bn err!\n");
				BN_free(nn);
				return -EINVAL;
			}
			OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, nn);
			OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e);
			BN_free(nn);
			BN_free(e);
			params = OSSL_PARAM_BLD_to_param(bld);
			OSSL_PARAM_BLD_free(bld);
			rsa = EVP_PKEY_fromdata(NULL, NULL, OSSL_KEYMGMT_SELECT_KEYPAIR, params);
			OSSL_PARAM_free(params);
			if (!rsa) {
				HPRE_TST_PRT("EVP_PKEY_fromdata err!\n");
				return -EINVAL;
			}
		}
		{
			EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(rsa, NULL);
			EVP_PKEY_encrypt_init(ctx);
			EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING);
			outlen = key_size;
			ret = EVP_PKEY_encrypt(ctx, ssl_out, &outlen, req->src, req->src_bytes);
			EVP_PKEY_CTX_free(ctx);
			if (ret != 1) {
				HPRE_TST_PRT("openssl pub encrypto fail!ret=%d\n", ret);
				return -ENOMEM;
			}
		}
		if (!g_config.soft_test && memcmp(ssl_out, req->dst, key_size)) {
			HPRE_TST_PRT("pub encrypto result  mismatch!\n");
			print_data(ssl_out, req->src_bytes, "openssl out");
			print_data(req->dst, req->dst_bytes, "hpre out");
			EVP_PKEY_print_private(stdout, rsa, 4, NULL);
			return -EINVAL;
		}
		free(ssl_out);
	} else {

		ssl_out = malloc(key_size);
		if (!ssl_out) {
			HPRE_TST_PRT("malloc ssl out fail!\n");
			return -ENOMEM;
		}

		if (key && wd_rsa_is_crt(sess)) {
			BIGNUM *dp, *dq, *iqmp, *p, *q;
			int size = key_size / 2;
			OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
			OSSL_PARAM *params;

			dq = hpre_bin_to_bn(key, size);
			dp = hpre_bin_to_bn(key + size, size);
			q = hpre_bin_to_bn(key + 2 * size, size);
			p = hpre_bin_to_bn(key + 3 * size, size);
			iqmp = hpre_bin_to_bn(key + 4 * size, size);
			nn = hpre_bin_to_bn(key + 7 * size, key_size);
			e = hpre_bin_to_bn(key + 5 * size, key_size);
			OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, nn);
			OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e);
			OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p);
			OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q);
			OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dp);
			OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dq);
			OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp);
			BN_free(dq); BN_free(dp); BN_free(q); BN_free(p); BN_free(iqmp);
			BN_free(nn); BN_free(e);
			params = OSSL_PARAM_BLD_to_param(bld);
			OSSL_PARAM_BLD_free(bld);
			rsa = EVP_PKEY_fromdata(NULL, NULL, OSSL_KEYMGMT_SELECT_KEYPAIR, params);
			OSSL_PARAM_free(params);
			if (!rsa) {
				HPRE_TST_PRT("EVP_PKEY_fromdata CRT err!\n");
				return -EINVAL;
			}

		} else if (key && !wd_rsa_is_crt(sess)) {
			BIGNUM *d;
			OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
			OSSL_PARAM *params;

			nn = hpre_bin_to_bn(key + key_size, key_size);
			if (!nn) {
				HPRE_TST_PRT("n bin2bn err!\n");
				return -EINVAL;
			}
			d = hpre_bin_to_bn(key, key_size);
			if (!d) {
				HPRE_TST_PRT("d bin2bn err!\n");
				BN_free(nn);
				return -EINVAL;
			}
			e = hpre_bin_to_bn(key + 2 * key_size, key_size);
			if (!e) {
				HPRE_TST_PRT("e bin2bn err!\n");
				BN_free(nn);
				BN_free(d);
				return -EINVAL;
			}
			OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, nn);
			OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e);
			OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d);
			BN_free(nn); BN_free(e); BN_free(d);
			params = OSSL_PARAM_BLD_to_param(bld);
			OSSL_PARAM_BLD_free(bld);
			rsa = EVP_PKEY_fromdata(NULL, NULL, OSSL_KEYMGMT_SELECT_KEYPAIR, params);
			OSSL_PARAM_free(params);
			if (!rsa) {
				HPRE_TST_PRT("EVP_PKEY_fromdata err!\n");
				return -EINVAL;
			}
		}

		{
			EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(rsa, NULL);
			EVP_PKEY_decrypt_init(ctx);
			EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING);
			outlen = key_size;
			ret = EVP_PKEY_decrypt(ctx, ssl_out, &outlen, req->src, req->src_bytes);
			EVP_PKEY_CTX_free(ctx);
			if (ret != 1) {
				HPRE_TST_PRT("openssl priv decrypto fail!ret=%d\n", ret);
				return -ENOMEM;
			}
		}

		#ifdef DEBUG
			print_data(req->dst, 16, "out");
			print_data(req->src, 16, "in");
			print_data(ssl_out, 16, "ssl_out");
		#endif

		if (!g_config.soft_test && memcmp(ssl_out, req->dst, ret)) {
			HPRE_TST_PRT("prv decrypto result  mismatch!\n");
			print_data(ssl_out, req->src_bytes, "openssl out");
			print_data(req->dst, req->dst_bytes, "hpre out");
			EVP_PKEY_print_private(stdout, rsa, 4, NULL);
			return -EINVAL;
		}
		free(ssl_out);

	}

	EVP_PKEY_free(rsa);

	return 0;
}

int hpre_sys_func_test(struct test_hpre_pthread_dt * pdata)
{
	int pid = getpid(), ret = 0, i = 0;
	int thread_id = (int)syscall(__NR_gettid);
	struct wd_rsa_sess_setup setup;
	struct wd_rsa_req req;
	handle_t sess;
	void *key_info = NULL;
	struct timeval cur_tval;
	float time = 0.0, speed = 0.0;
	const char *alg_name = pdata->alg_name;
	int key_size = g_config.key_bits >> 3;
        char m[] = {0x54, 0x85, 0x9b, 0x34, 0x2c, 0x49, 0xea, 0x2a};

	if (g_config.perf_test && (!g_config.times && !g_config.seconds)) {
		HPRE_TST_PRT("g_config.times or  g_config.seconds err\n");
		return -1;
	}

new_test_again:

	memset(&setup, 0, sizeof(setup));
	memset(&req, 0, sizeof(req));
	setup.key_bits = g_config.key_bits;
	if (!strcmp(g_config.alg_mode, "crt"))
		setup.is_crt = true;
	else
		setup.is_crt = false;

	sess = wd_rsa_alloc_sess(&setup);
	if (!sess) {
		HPRE_TST_PRT("Proc-%d, %d-TD:create %s sess fail!\n",
			     pid, thread_id, alg_name);
		ret = -EINVAL;
		goto fail_release;
	}

	/* Just make sure memory size is enough */
	key_info = malloc(key_size * 16);
	if (!key_info) {
		HPRE_TST_PRT("thrd-%d:malloc key!\n", thread_id);
		goto fail_release;
	}

	rsa_key_in = malloc(2 * key_size + sizeof(struct hpre_rsa_test_key_in));
	if (!rsa_key_in) {
		HPRE_TST_PRT("thrd-%d:malloc err!\n", thread_id);
		goto fail_release;
	}

	rsa_key_in->e = rsa_key_in + 1;
	rsa_key_in->p = rsa_key_in->e + key_size;
	rsa_key_in->q = rsa_key_in->p + (key_size >> 1);

	memset(key_info, 0, key_size * 16);

		ret = test_rsa_key_gen(sess, NULL, key_info, key_info, 0);
		if (ret) {
			HPRE_TST_PRT("thrd-%d:Openssl key gen fail!\n", thread_id);
			goto fail_release;
		}
		ret = get_rsa_key_from_test_sample(sess, NULL, key_info, key_info, 0);
		if (ret) {
			HPRE_TST_PRT("thrd-%d:get sample key fail!\n", thread_id);
			goto fail_release;
		}

	/* always key size bytes input */
	req.src_bytes = key_size;
	if (pdata->op_type == RSA_KEY_GEN) {
		req.op_type = WD_RSA_GENKEY;
	} else if (pdata->op_type == RSA_PUB_EN) {
		req.op_type = WD_RSA_VERIFY;
	} else if (pdata->op_type == RSA_PRV_DE) {
		req.op_type = WD_RSA_SIGN;
	} else {
		HPRE_TST_PRT("thrd-%d:optype=%d err!\n",
			  thread_id, pdata->op_type);
		goto fail_release;
	}

	if (req.op_type == WD_RSA_GENKEY) {
		ret = hpre_test_fill_keygen_opdata(sess, &req);
		if (ret){
			HPRE_TST_PRT("fill key gen req fail!\n");
			goto fail_release;
		}
	} else {
		req.src = malloc(key_size);
		if (!req.src) {
			HPRE_TST_PRT("alloc in buffer fail!\n");
			goto fail_release;
		}
		memset(req.src, 0, req.src_bytes);
                memcpy(req.src + key_size - sizeof(m), m, sizeof(m));
		req.dst = malloc(key_size);
		if (!req.dst) {
			HPRE_TST_PRT("alloc out buffer fail!\n");
			goto fail_release;
		}
		req.dst_bytes = key_size;
	}

	do {
		if (!g_config.soft_test) {
			ret = wd_do_rsa_sync(sess, &req);
			if (ret || req.status) {
				HPRE_TST_PRT("Proc-%d, T-%d:hpre %s %dth status=%d fail!\n",
					 pid, thread_id,
					 g_config.op, i, req.status);
				goto fail_release;
			}
		}

		pdata->send_task_num++;
		i++;
		if (g_config.check) {
			void *check_key;

			if (req.op_type == WD_RSA_SIGN)
				check_key = key_info;
			if (req.op_type == WD_RSA_VERIFY)
				if (wd_rsa_is_crt(sess))
					check_key = key_info + 5 * (g_config.key_bits >> 4);
				else
					check_key = key_info + 2 * key_size;
			else
				check_key = key_info;
			ret = hpre_test_result_check(sess, &req, check_key);
			if (ret) {
				HPRE_TST_PRT("P-%d,T-%d:hpre %s %dth mismth\n",
						 pid, thread_id,
						 g_config.op, i);
				goto fail_release;
			}
			else {
				if (req.op_type == WD_RSA_GENKEY) {
					if (is_allow_print(i, WD_RSA_GENKEY,  pdata->thread_num))
						HPRE_TST_PRT("HPRE hardware key generate successfully!\n");
				}
			}
		}

		/* clean output buffer remainings in the last time operation */
		if (req.op_type == WD_RSA_GENKEY) {
			char *data;
			int len;

			len = wd_rsa_kg_out_data((void *)req.dst, &data);
			if (len < 0) {
				HPRE_TST_PRT("wd rsa get key gen out data fail!\n");
				goto fail_release;
			}
			memset(data, 0, len);
		} else {
#ifdef DEBUG
			print_data(req.dst, 16, "out");
#endif
		}
		if (is_allow_print(i, pdata->op_type, pdata->thread_num)) {
			gettimeofday(&cur_tval, NULL);
			time = (float)((cur_tval.tv_sec - pdata->start_tval.tv_sec) * 1000000 +
						   (cur_tval.tv_usec - pdata->start_tval.tv_usec));
			speed = 1 / (time / i) * 1000;
			HPRE_TST_PRT("Proc-%d, %d-TD %s %dtimes,%0.0fus, %0.3fkops\n",
					 pid, thread_id, g_config.op,
					 i, time, speed);
		}

		if (!g_config.perf_test && !g_config.soft_test) {
			if (req.op_type == WD_RSA_GENKEY) {
				if (req.src)
					wd_rsa_del_kg_in(sess, req.src);
				if (req.dst)
					wd_rsa_del_kg_out(sess, req.dst);
			} else {
				if (req.src)
					free(req.src);
				if (req.dst)
					free(req.dst);
			}

			if (sess)
				wd_rsa_free_sess(sess);

			if (rsa_key_in)
				free(rsa_key_in);

			if (key_info)
				free(key_info);

			if (is_exit(pdata))
				return 0;

			goto new_test_again;
		}
	}while(!is_exit(pdata));

	pdata->recv_task_num = pdata->send_task_num;

	if (g_config.perf_test) {
		gettimeofday(&cur_tval, NULL);
		time = (float)((cur_tval.tv_sec -pdata->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - pdata->start_tval.tv_usec);

		if (g_config.seconds) {
			speed = pdata->recv_task_num / time * 1000000;
		} else if (g_config.times) {
			speed = pdata->recv_task_num * 1.0 * 1000 * 1000 / time;
		}
		pdata->perf = speed;
		HPRE_TST_PRT("<< Proc-%d, %d-TD: run %s %s mode %u key_bits at %0.3f ops!\n",
			pid, thread_id, g_config.op, g_config.alg_mode, g_config.key_bits, speed);
	}

fail_release:
	if (req.op_type == WD_RSA_GENKEY) {
		if (req.src)
			wd_rsa_del_kg_in(sess, req.src);
		if (req.dst)
			wd_rsa_del_kg_out(sess, req.dst);
	} else {
		if (req.src)
			free(req.src);
		if (req.dst)
			free(req.dst);
	}
	if (sess)
		wd_rsa_free_sess(sess);
	if (key_info)
		free(key_info);
	if (rsa_key_in)
		free(rsa_key_in);


	return ret;
}

void *_hpre_rsa_sys_test_thread(void *data)
{
	int ret, cpuid;
	struct test_hpre_pthread_dt *pdata = data;
	cpu_set_t mask;
	int pid = getpid();
	int thread_id = (int)syscall(__NR_gettid);

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	CPU_SET(cpuid, &mask);
	if (cpuid) {
		ret = pthread_setaffinity_np(pthread_self(),
					 sizeof(mask), &mask);
		if (ret < 0) {
			HPRE_TST_PRT("Proc-%d, thrd-%d:set affinity fail!\n",
				 pid, thread_id);
			return NULL;
		}
		HPRE_TST_PRT("Proc-%d, thrd-%d bind to cpu-%d!\n",
				pid, thread_id, cpuid);
	}
	ret = hpre_sys_func_test(pdata);
	if (ret)
		return NULL;

	return NULL;
}

static int hpre_sys_test(int thread_num, __u64 lcore_mask,
			 __u64 hcore_mask, enum alg_op_type op_type,
			char *dev_path, unsigned int node_msk)
{
	int i, ret, cnt = 0;
	int h_cpuid;
	float speed = 0.0;

	if (_get_one_bits(lcore_mask) > 0)
		cnt =  _get_one_bits(lcore_mask);
	else if (_get_one_bits(lcore_mask) == 0 &&
		 _get_one_bits(hcore_mask) == 0)
		cnt = thread_num;
	for (i = 0; i < cnt; i++) {
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].cpu_id = _get_cpu_id(i, lcore_mask);
		gettimeofday(&test_thrds_data[i].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i], NULL,
				    _hpre_sys_test_thread, &test_thrds_data[i]);
		if (ret) {
			HPRE_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}
	for (i = 0; i < thread_num - cnt; i++) {
		h_cpuid = _get_cpu_id(i, hcore_mask);
		if (h_cpuid > 0)
			h_cpuid += 64;

		test_thrds_data[i + cnt].thread_num = thread_num;
		test_thrds_data[i + cnt].op_type = op_type;
		test_thrds_data[i + cnt].cpu_id = h_cpuid;
		gettimeofday(&test_thrds_data[i + cnt].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i + cnt], NULL,
				 _hpre_sys_test_thread, &test_thrds_data[i + cnt]);
		if (ret) {
			HPRE_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}
	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			HPRE_TST_PRT("Join %dth thread fail!\n", i);
			return ret;
		}
		speed += test_thrds_data[i].perf;
	}

	if (g_config.perf_test)
		HPRE_TST_PRT("<< %s %u thread %s %s mode %u key_bits at %0.3f ops!\n",
			g_config.trd_mode, g_config.trd_num, g_config.op,
			g_config.alg_mode, g_config.key_bits, speed);
	HPRE_TST_PRT("<< test finish!\n");

	return 0;
}

static void  *_rsa_async_poll_test_thread(void *data)
{
	__u32 count = 0;
	__u32 expt = 0;
	int ret = 0;

	while (1) {
		ret = wd_rsa_poll(expt, &count);
		if (ret < 0) {
			break;
		}

		if (asyn_thread_exit)
			break;
	}

	if (g_config.with_log)
		HPRE_TST_PRT("%s exit!\n", __func__);

	return NULL;
}
static void _rsa_cb(void *req_t)
{
	struct wd_rsa_req *req = req_t;
	int keybits, key_size;
	struct rsa_async_tag *tag = req->cb_param;
	handle_t sess = tag->sess;
	int thread_id = tag->thread_id;
	int cnt = tag->cnt;
	void *out = req->dst;
	enum wd_rsa_op_type  op_type = req->op_type;
	struct wd_rsa_prikey *prikey;
	struct test_hpre_pthread_dt *thread_info = tag->thread_info;

	wd_rsa_get_prikey(sess, &prikey);
	keybits = wd_rsa_get_key_bits(sess);
	key_size = keybits >> 3;

	thread_info->recv_task_num++;

	if (g_config.check) {
		if (op_type == WD_RSA_GENKEY) {
			struct wd_rsa_kg_out *kout = out;

			if (wd_rsa_is_crt(sess)) {
				struct wd_dtb qinv, dq, dp;
				struct wd_dtb *s_qinv, *s_dq, *s_dp;

				wd_rsa_get_crt_prikey_params(prikey, &s_dq, &s_dp,
								&s_qinv, NULL, NULL);
				wd_rsa_get_kg_out_crt_params(kout, &qinv, &dq, &dp);
				if (memcmp(s_qinv->data, qinv.data, s_qinv->bsize)) {
					HPRE_TST_PRT("keygen  qinv  mismatch!\n");
					return;
				}
				if (memcmp(s_dq->data, dq.data, s_dq->bsize)) {
					HPRE_TST_PRT("keygen  dq mismatch!\n");
					return;
				}
				if (memcmp(s_dp->data, dp.data, s_dp->bsize)) {
					HPRE_TST_PRT("keygen  dp  mismatch!\n");
					return;
				}

			} else {
				struct wd_dtb d, n;
				struct wd_dtb *s_d, *s_n;

				wd_rsa_get_prikey_params(prikey, &s_d, &s_n);
				wd_rsa_get_kg_out_params(kout, &d, &n);

				/* check D */
				if (memcmp(s_d->data, d.data, s_d->bsize)) {
					HPRE_TST_PRT("key generate D result mismatching!\n");
					return;
				}
				if (memcmp(s_n->data, n.data, s_n->bsize)) {
					HPRE_TST_PRT("key generate N result mismatching!\n");
					return;
				}
			}
			if (is_allow_print(cnt, DH_ASYNC_GEN, 1))
				HPRE_TST_PRT("HPRE hardware key generate successfully!\n");
		} else if (op_type == WD_RSA_VERIFY) {
			if (!g_config.soft_test && memcmp(ssl_params.ssl_verify_result, out, key_size)) {
				HPRE_TST_PRT("pub encrypto result  mismatch!\n");
				return;
			}
		} else {
			if (wd_rsa_is_crt(sess))
				if (!g_config.soft_test && memcmp(ssl_params.ssl_sign_result, out, key_size)) {
					HPRE_TST_PRT("prv decrypto result  mismatch!\n");
					return;
				}
		}
	}

	if (is_allow_print(cnt, op_type, 1))
		HPRE_TST_PRT("thread %d do RSA %dth time success!\n", thread_id, cnt);
	if (op_type == WD_RSA_GENKEY && out) {
		wd_rsa_del_kg_out(sess, out);
	}
	free(tag);
}

void *_rsa_async_op_test_thread(void *data)
{
	int ret = 0, i = 0, cpuid;
	struct test_hpre_pthread_dt *pdata = data;
	const char *alg_name = pdata->alg_name;
	cpu_set_t mask;
	enum alg_op_type op_type;
	int pid = getpid();
	int thread_id = (int)syscall(__NR_gettid);
	struct wd_rsa_sess_setup setup;
	struct wd_rsa_req req;
	handle_t sess;
	void *key_info = NULL;
	struct wd_rsa_prikey *prikey;
	struct wd_rsa_pubkey *pubkey;
	struct rsa_async_tag *tag;
	struct wd_dtb *wd_e, *wd_d, *wd_n, *wd_dq, *wd_dp, *wd_qinv, *wd_q, *wd_p;
	struct wd_dtb t_e, t_p, t_q;
	u32 key_size = g_config.key_bits >> 3;

	if (g_config.perf_test && (!g_config.times && !g_config.seconds)) {
		HPRE_TST_PRT("g_config.times or  g_config.seconds err\n");
		return NULL;
	}

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	op_type = pdata->op_type;
	CPU_SET(cpuid, &mask);
	if (cpuid) {
		ret = pthread_setaffinity_np(pthread_self(),
					 sizeof(mask), &mask);
		if (ret < 0) {
			HPRE_TST_PRT("Proc-%d, thrd-%d:set affinity fail!\n",
				 pid, thread_id);
			return NULL;
		}
		HPRE_TST_PRT("Proc-%d, thrd-%d bind to cpu-%d!\n",
				pid, thread_id, cpuid);
	}
	memset(&setup, 0, sizeof(setup));
	memset(&req, 0, sizeof(req));
	setup.key_bits = g_config.key_bits;
	if (!strcmp(g_config.alg_mode, "crt"))
		setup.is_crt = true;
	else
		setup.is_crt = false;

	sess = wd_rsa_alloc_sess(&setup);
	if (!sess) {
		HPRE_TST_PRT("Proc-%d, %d-TD:create %s sess fail!\n",
			     pid, thread_id, alg_name);
		goto fail_release;
	}

	rsa_key_in = malloc(2 * key_size + sizeof(struct hpre_rsa_test_key_in));
	if (!rsa_key_in) {
		HPRE_TST_PRT("thrd-%d:malloc err!\n", thread_id);
		goto fail_release;
	}

	rsa_key_in->e = rsa_key_in + 1;
	rsa_key_in->p = rsa_key_in->e + key_size;
	rsa_key_in->q = rsa_key_in->p + (key_size >> 1);

	wd_rsa_get_pubkey(sess, &pubkey);
	wd_rsa_get_pubkey_params(pubkey, &wd_e, &wd_n);

	wd_e->dsize = BN_bn2bin(ssl_params.e, (unsigned char *)wd_e->data);
	if (wd_e->dsize > wd_e->bsize) {
		HPRE_TST_PRT("e bn to bin overflow!\n");
		goto fail_release;
	}
	wd_n->dsize = BN_bn2bin(ssl_params.n, (unsigned char *)wd_n->data);
	if (wd_n->dsize > wd_n->bsize) {
		HPRE_TST_PRT("n bn to bin overflow!\n");
		goto fail_release;
	}
	memcpy(wd_e->data, ssl_params.e, key_size);
	wd_e->dsize = key_size;
	memcpy(wd_n->data, ssl_params.n, key_size);
	wd_n->dsize = key_size;
	wd_rsa_get_prikey(sess, &prikey);
	if (wd_rsa_is_crt(sess)) {
		wd_rsa_get_crt_prikey_params(prikey, &wd_dq, &wd_dp, &wd_qinv, &wd_q, &wd_p);

		/* CRT mode private key */
		wd_dq->dsize = BN_bn2bin(ssl_params.dq, (unsigned char *)wd_dq->data);
		if (wd_dq->dsize > wd_dq->bsize) {
			HPRE_TST_PRT("dq bn to bin overflow!\n");
			goto fail_release;
		}
		wd_dp->dsize = BN_bn2bin(ssl_params.dp, (unsigned char *)wd_dp->data);
		if (wd_dp->dsize > wd_dp->bsize) {
			HPRE_TST_PRT("dp bn to bin overflow!\n");
			goto fail_release;
		}
		wd_qinv->dsize = BN_bn2bin(ssl_params.qinv, (unsigned char *)wd_qinv->data);
		if (wd_qinv->dsize > wd_qinv->bsize) {
			HPRE_TST_PRT("qinv bn to bin overflow!\n");
			goto fail_release;
		}
		wd_q->dsize = BN_bn2bin(ssl_params.q, (unsigned char *)wd_q->data);
		if (wd_q->dsize > wd_q->bsize) {
			HPRE_TST_PRT("q bn to bin overflow!\n");
			goto fail_release;
		}
		wd_p->dsize = BN_bn2bin(ssl_params.p, (unsigned char *)wd_p->data);
		if (wd_p->dsize > wd_p->bsize) {
			HPRE_TST_PRT("p bn to bin overflow!\n");
			goto fail_release;
		}
		memcpy(wd_dq->data, ssl_params.dq, key_size / 2);
		wd_dq->dsize = key_size / 2;
		memcpy(wd_dp->data, ssl_params.dp, key_size / 2);
		wd_dp->dsize = key_size / 2;
		memcpy(wd_qinv->data, ssl_params.qinv, key_size / 2);
		wd_qinv->dsize = key_size / 2;
		memcpy(wd_q->data, ssl_params.q, key_size / 2);
		wd_q->dsize = key_size / 2;
		memcpy(wd_p->data, ssl_params.p, key_size / 2);
		wd_p->dsize = key_size / 2;

	} else {
		wd_rsa_get_prikey_params(prikey, &wd_d, &wd_n);

		wd_d->dsize = BN_bn2bin(ssl_params.d, (unsigned char *)wd_d->data);
		wd_n->dsize = BN_bn2bin(ssl_params.n, (unsigned char *)wd_n->data);
		memcpy(wd_d->data, ssl_params.d, key_size);
		wd_d->dsize = key_size;
		memcpy(wd_n->data, ssl_params.n, key_size);
		wd_n->dsize = key_size;
		wd_e = &t_e;
		wd_p = &t_p;
		wd_q = &t_q;
		memset(rsa_key_in->e, 0, key_size);
		memset(rsa_key_in->p, 0, key_size >> 1);
		memset(rsa_key_in->q, 0, key_size >> 1);
		rsa_key_in->e_size = BN_bn2bin(ssl_params.e, (unsigned char *)rsa_key_in->e);
		rsa_key_in->p_size = BN_bn2bin(ssl_params.p, (unsigned char *)rsa_key_in->p);
		rsa_key_in->q_size = BN_bn2bin(ssl_params.q, (unsigned char *)rsa_key_in->q);
		memcpy(rsa_key_in->e, ssl_params.e, key_size);
		rsa_key_in->e_size = key_size;
		memcpy(rsa_key_in->p, ssl_params.p, key_size / 2);
		rsa_key_in->p_size = key_size / 2;
		memcpy(rsa_key_in->q, ssl_params.q, key_size / 2);
		rsa_key_in->q_size = key_size / 2;
		wd_e->data = rsa_key_in->e;
		wd_e->dsize = rsa_key_in->e_size;
		wd_p->data = rsa_key_in->p;
		wd_p->dsize = rsa_key_in->p_size;
		wd_q->data = rsa_key_in->q;
		wd_q->dsize = rsa_key_in->q_size;
	}

	/* always key size bytes input */
	req.src_bytes = key_size;
	req.cb = _rsa_cb;
	if (op_type == RSA_KEY_GEN || op_type == RSA_ASYNC_GEN) {
		req.op_type = WD_RSA_GENKEY;
	} else if (op_type == RSA_PUB_EN || op_type == RSA_ASYNC_EN) {
		req.op_type = WD_RSA_VERIFY;
	} else if (op_type == RSA_PRV_DE || op_type == RSA_ASYNC_DE) {
		req.op_type = WD_RSA_SIGN;
	} else {
		HPRE_TST_PRT("thrd-%d:optype=%d err!\n",
			  thread_id, op_type);
		goto fail_release;
	}

	if (req.op_type == WD_RSA_GENKEY) {
		req.src = (__u8 *)wd_rsa_new_kg_in(sess, wd_e, wd_p, wd_q);
		if (!req.src) {
			HPRE_TST_PRT("thrd-%d:fill key gen req fail!\n",
				     thread_id);
			goto fail_release;
		}
		//req.dst = wd_rsa_new_kg_out(sess);
		//if (!req.dst) {
		//	HPRE_TST_PRT("create rsa kgen out fail!\n");
		//	goto fail_release;
		//}
	} else {
		req.src = malloc(key_size);
		if (!req.src) {
			HPRE_TST_PRT("alloc in buffer fail!\n");
			goto fail_release;
		}
		memset(req.src, 0, req.src_bytes);
		req.dst = malloc(key_size);
		if (!req.dst) {
			HPRE_TST_PRT("alloc out buffer fail!\n");
			goto fail_release;
		}
		memset(req.dst, 0, req.src_bytes);
		req.dst_bytes = key_size;
	}

	do {
			if (req.op_type == WD_RSA_GENKEY) {
				req.dst = wd_rsa_new_kg_out(sess);
				if (!req.dst) {
					HPRE_TST_PRT("create rsa kgen out fail!\n");
					goto fail_release;
				}
			}
			/* set the user tag */
			tag = malloc(sizeof(*tag));
			if (!tag)
				goto fail_release;
			tag->sess = sess;
			tag->thread_id = thread_id;
			tag->cnt = i;
			tag->thread_info = pdata;
			req.cb_param = tag;
try_do_again:
			ret = wd_do_rsa_async(sess, &req);
			if (ret == -WD_EBUSY) {
				usleep(100);
				goto try_do_again;
			} else if (ret) {
				HPRE_TST_PRT("Proc-%d, T-%d:hpre %s %dth fail!\n",
					 pid, thread_id, g_config.op, i);
				goto fail_release;
			}
			//usleep(100);
			i++;
			pdata->send_task_num++;
	}while (!is_exit(pdata));

	if (g_config.perf_test) {
		struct timeval cur_tval;
		float speed = 0.0, time_used = 0.0;
		gettimeofday(&cur_tval, NULL);

		//printf("start: s %lu, us %lu\n", pdata->start_tval.tv_sec, pdata->start_tval.tv_usec);
		//printf("now: s %lu, us %lu\n", cur_tval.tv_sec, cur_tval.tv_usec);

		time_used = (float)((cur_tval.tv_sec -pdata->start_tval.tv_sec) * 1000000 +
				cur_tval.tv_usec - pdata->start_tval.tv_usec);

		if (g_config.seconds) {
			speed = pdata->recv_task_num / time_used * 1000000;
		} else if (g_config.times) {
			speed = pdata->recv_task_num * 1.0 * 1000 * 1000 / time_used;
		}
		HPRE_TST_PRT("<< Proc-%d, %d-TD: run %s %s mode %u key_bits at %0.3f ops!\n",
			pid, thread_id, g_config.op, g_config.alg_mode, g_config.key_bits, speed);
		pdata->perf = speed;
	}

	/* wait for recv finish */
	while (pdata->send_task_num != pdata->recv_task_num) {
		usleep(1000 * 1000);
		if (g_config.with_log)
			HPRE_TST_PRT("<< Proc-%d, %d-TD: total send %u: recv %u, wait recv finish...!\n",
				pid, thread_id, pdata->send_task_num, pdata->recv_task_num);
	}


fail_release:
	if (req.op_type == WD_RSA_GENKEY) {
		if (req.src)
			wd_rsa_del_kg_in(sess, req.src);
		//if (req.dst)
		//	wd_rsa_del_kg_out(sess, req.dst);
	} else {
		if (req.src)
			free(req.src);
		if (req.dst)
			free(req.dst);
	}
	if (sess)
		wd_rsa_free_sess(sess);
	if (key_info)
		free(key_info);
	if (rsa_key_in)
		free(rsa_key_in);
	return NULL;
}

static int set_ssl_plantext(void)
{
	ssl_params.size = g_config.key_bits >> 3;
	ssl_params.plantext = malloc(ssl_params.size);
	if (!ssl_params.plantext)
		return -ENOMEM;
	memset(ssl_params.plantext, 0, ssl_params.size);
	return 0;
}

static int rsa_openssl_key_gen_for_async_test(void)
{
	EVP_PKEY *rsa = NULL;
	EVP_PKEY_CTX *genctx = NULL;
	int ret;
	size_t outlen;

	genctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!genctx) {
		HPRE_TST_PRT("EVP_PKEY_CTX_new_from_name fail!\n");
		return -ENOMEM;
	}
	ret = EVP_PKEY_keygen_init(genctx);
	if (ret != 1) {
		HPRE_TST_PRT("EVP_PKEY_keygen_init fail!\n");
		ret = -1;
		goto gen_fail;
	}
	ret = EVP_PKEY_CTX_set_rsa_keygen_bits(genctx, g_config.key_bits);
	if (ret != 1) {
		HPRE_TST_PRT("EVP_PKEY_CTX_set_rsa_keygen_bits fail!\n");
		ret = -1;
		goto gen_fail;
	}
	ret = EVP_PKEY_keygen(genctx, &rsa);
	EVP_PKEY_CTX_free(genctx);
	genctx = NULL;
	if (ret != 1) {
		HPRE_TST_PRT("EVP_PKEY_keygen fail!\n");
		ret = -1;
		goto gen_fail;
	}

	ssl_params.e = NULL;
	ssl_params.n = NULL;
	ssl_params.d = NULL;
	ssl_params.p = NULL;
	ssl_params.q = NULL;
	ssl_params.dp = NULL;
	ssl_params.dq = NULL;
	ssl_params.qinv = NULL;
	EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_N, &ssl_params.n);
	EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_E, &ssl_params.e);
	EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_D, &ssl_params.d);
	EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_FACTOR1, &ssl_params.p);
	EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_FACTOR2, &ssl_params.q);
	EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_EXPONENT1, &ssl_params.dp);
	EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_EXPONENT2, &ssl_params.dq);
	EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &ssl_params.qinv);

	/* Generate OpenSSL SW rsa verify and sign standard result
	 * for check in the next tests
	 */
	ret = set_ssl_plantext();
	if (ret) {
		HPRE_TST_PRT("set ssl plantext fail!!\n");
		ret = -1;
		goto gen_fail;
	}
	ssl_params.ssl_verify_result = malloc(ssl_params.size);
	if (!ssl_params.ssl_verify_result) {
		HPRE_TST_PRT("malloc verify result buffer fail!!\n");
		ret = -1;
		goto gen_fail;
	}
	{
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(rsa, NULL);
		EVP_PKEY_encrypt_init(ctx);
		EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING);
		outlen = ssl_params.size;
		ret = EVP_PKEY_encrypt(ctx, ssl_params.ssl_verify_result, &outlen,
		ssl_params.plantext, ssl_params.size);
		EVP_PKEY_CTX_free(ctx);
		if (ret != 1 || outlen != ssl_params.size) {
			HPRE_TST_PRT("openssl pub encrypto fail!ret=%d\n", ret);
			ret = -1;
			return ret;
		}
	}
	ssl_params.ssl_sign_result = malloc(ssl_params.size);
	if (!ssl_params.ssl_sign_result) {
		HPRE_TST_PRT("malloc sign result buffer fail!!\n");
		ret = -1;
		goto gen_fail;
	}
	{
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(rsa, NULL);
		EVP_PKEY_decrypt_init(ctx);
		EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING);
		outlen = ssl_params.size;
		ret = EVP_PKEY_decrypt(ctx, ssl_params.ssl_sign_result, &outlen,
		ssl_params.plantext, ssl_params.size);
		EVP_PKEY_CTX_free(ctx);
		if (ret != 1 || outlen != ssl_params.size) {
			HPRE_TST_PRT("openssl priv decrypto fail!ret=%d\n", ret);
			ret = -1;
			goto gen_fail;
		}
	}

	return 0;

	gen_fail:
	EVP_PKEY_free(rsa);
	EVP_PKEY_CTX_free(genctx);
	BN_free(ssl_params.e);
	if (ssl_params.plantext)
		free(ssl_params.plantext);
	if (ssl_params.ssl_verify_result)
		free(ssl_params.ssl_verify_result);
	if (ssl_params.ssl_sign_result)
		free(ssl_params.ssl_sign_result);
	return ret;
}

static int rsa_sample_key_gen_for_async_test(void)
{
	const __u8 *p, *q, *n, *e, *d, *dp, *dq, *qinv;
	int key_bits = g_config.key_bits;
	int ret;

	if (g_config.key_bits == 1024) {
		e = rsa_e_1024;
		p = rsa_p_1024;
		q = rsa_q_1024;
		dp = rsa_dp_1024;
		dq = rsa_dq_1024;
		qinv = rsa_qinv_1024;
		d = rsa_d_1024;
		n = rsa_n_1024;
	} else if (key_bits == 2048) {
		e = rsa_e_2048;
		p = rsa_p_2048;
		q = rsa_q_2048;
		dp = rsa_dp_2048;
		dq = rsa_dq_2048;
		qinv = rsa_qinv_2048;
		d = rsa_d_2048;
		n = rsa_n_2048;
	} else if (key_bits == 3072) {
		e = rsa_e_3072;
		p = rsa_p_3072;
		q = rsa_q_3072;
		dp = rsa_dp_3072;
		dq = rsa_dq_3072;
		qinv = rsa_qinv_3072;
		d = rsa_d_3072;
		n = rsa_n_3072;
	} else if (key_bits == 4096) {
		e = rsa_e_4096;
		p = rsa_p_4096;
		q = rsa_q_4096;
		dp = rsa_dp_4096;
		dq = rsa_dq_4096;
		qinv = rsa_qinv_4096;
		d = rsa_d_4096;
		n = rsa_n_4096;
	} else {
		HPRE_TST_PRT("invalid key bits = %d!\n", key_bits);
		return -1;
	}

	ssl_params.e = BN_bin2bn(e, key_bits >> 3, NULL);
	if (!ssl_params.e) {
		HPRE_TST_PRT("Bin2bin e fail!\n");
		ret = -ENOMEM;
		goto gen_fail;
	}

	ssl_params.d = BN_bin2bn(d, key_bits >> 3, NULL);
	if (!ssl_params.d) {
		HPRE_TST_PRT("Bin2bin d fail!\n");
		ret = -ENOMEM;
		goto gen_fail;
	}

	ssl_params.n = BN_bin2bn(n, key_bits >> 3, NULL);
	if (!ssl_params.n) {
		HPRE_TST_PRT("Bin2bin n fail!\n");
		ret = -ENOMEM;
		goto gen_fail;
	}

	ssl_params.p = BN_bin2bn(p, key_bits >> 4, NULL);
	if (!ssl_params.p) {
		HPRE_TST_PRT("Bin2bin p fail!\n");
		ret = -ENOMEM;
		goto gen_fail;
	}

	ssl_params.q = BN_bin2bn(q, key_bits >> 4, NULL);
	if (!ssl_params.q) {
		HPRE_TST_PRT("Bin2bin q fail!\n");
		ret = -ENOMEM;
		goto gen_fail;
	}

	ssl_params.dp = BN_bin2bn(dp, key_bits >> 4, NULL);
	if (!ssl_params.dp) {
		HPRE_TST_PRT("Bin2bin dp fail!\n");
		ret = -ENOMEM;
		goto gen_fail;
	}

	ssl_params.dq = BN_bin2bn(dq, key_bits >> 4, NULL);
	if (!ssl_params.dq) {
		HPRE_TST_PRT("Bin2bin dq fail!\n");
		ret = -ENOMEM;
		goto gen_fail;
	}

	ssl_params.qinv = BN_bin2bn(qinv, key_bits >> 4, NULL);
	if (!ssl_params.qinv) {
		HPRE_TST_PRT("Bin2bin qinv fail!\n");
		ret = -ENOMEM;
		goto gen_fail;
	}

	/* Generate OpenSSL SW rsa verify and sign standard result
	 * for check in the next tests
	 */
	ret = set_ssl_plantext();
	if (ret) {
		HPRE_TST_PRT("set ssl plantext fail!!\n");
		ret = -1;
		goto gen_fail;
	}

	ssl_params.ssl_verify_result = malloc(ssl_params.size);
	if (!ssl_params.ssl_verify_result) {
		HPRE_TST_PRT("malloc verify result buffer fail!!\n");
		ret = -1;
		goto gen_fail;
	}
	ssl_params.ssl_sign_result = malloc(ssl_params.size);
	if (!ssl_params.ssl_sign_result) {
		HPRE_TST_PRT("malloc sign result buffer fail!!\n");
		ret = -1;
		goto gen_fail;
	}

	return 0;
gen_fail:
	if (ssl_params.e)
		BN_free(ssl_params.e);
	if (ssl_params.d)
		BN_free(ssl_params.d);
	if (ssl_params.n)
		BN_free(ssl_params.n);
	if (ssl_params.p)
		BN_free(ssl_params.p);
	if (ssl_params.q)
		BN_free(ssl_params.q);
	if (ssl_params.dp)
		BN_free(ssl_params.dp);
	if (ssl_params.dq)
		BN_free(ssl_params.dq);
	if (ssl_params.qinv)
		BN_free(ssl_params.qinv);
	if (ssl_params.plantext)
		free(ssl_params.plantext);
	if (ssl_params.ssl_verify_result)
		free(ssl_params.ssl_verify_result);
	if (ssl_params.ssl_sign_result)
		free(ssl_params.ssl_sign_result);
	return ret;
}
#endif

static int rsa_async_test(int thread_num, __u64 lcore_mask,
			 __u64 hcore_mask, enum alg_op_type op_type)
{
	int ret = 0, cnt = 0, i;
	int h_cpuid;
	float speed = 0.0;

	/* Create poll thread at first */
	test_thrds_data[0].thread_num = 1;
	test_thrds_data[0].op_type = op_type;
	test_thrds_data[0].cpu_id = 0;
	ret = pthread_create(&system_test_thrds[0], NULL,
		_rsa_async_poll_test_thread, &test_thrds_data[0]);
	if (ret) {
		HPRE_TST_PRT("Create poll thread fail!\n");
		return ret;
	}
	ret = rsa_openssl_key_gen_for_async_test();
	if(ret) {
		HPRE_TST_PRT("openssl genkey for async thread test fail!");
		return 0;
	}
	ret = rsa_sample_key_gen_for_async_test();
	if(ret) {
		HPRE_TST_PRT("sample genkey for async thread test fail!");
		return 0;
	}

	if (_get_one_bits(lcore_mask) > 0)
		cnt =  _get_one_bits(lcore_mask);
	else if (_get_one_bits(lcore_mask) == 0 &&
		 _get_one_bits(hcore_mask) == 0)
		cnt = thread_num;
	for (i = 1; i <= cnt; i++) {
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].cpu_id = _get_cpu_id(i - 1, lcore_mask);
		gettimeofday(&test_thrds_data[i].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i], NULL,
				    _rsa_async_op_test_thread, &test_thrds_data[i]);
		if (ret) {
			HPRE_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}
	for (i = 1; i <= thread_num - cnt; i++) {
		h_cpuid = _get_cpu_id(i - 1, hcore_mask);
		if (h_cpuid > 0)
			h_cpuid += 64;
		test_thrds_data[i + cnt].thread_num = thread_num;
		test_thrds_data[i + cnt].op_type = op_type;
		test_thrds_data[i + cnt].cpu_id = h_cpuid;
		gettimeofday(&test_thrds_data[i + cnt].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i + cnt], NULL,
				 _rsa_async_op_test_thread, &test_thrds_data[i + cnt]);
		if (ret) {
			HPRE_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}
	for (i = 1; i <= thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			HPRE_TST_PRT("Join %dth thread fail!\n", i);
			return ret;
		}
		speed += test_thrds_data[i].perf;
	}

	asyn_thread_exit = 1;

	ret = pthread_join(system_test_thrds[0], NULL);
	if (ret) {
		HPRE_TST_PRT("Join %dth thread fail!\n", i);
		return ret;
	}

	if (g_config.perf_test)
		HPRE_TST_PRT("<< %s %u thread %s %s mode %u key_bits at %0.3f ops!\n",
			g_config.trd_mode, g_config.trd_num, g_config.op,
			g_config.alg_mode, g_config.key_bits, speed);
	HPRE_TST_PRT("<< test finish!\n");
	return 0;
}

static void *_dh_async_poll_test_thread(void *data)
{
	struct test_hpre_pthread_dt *pdata = data;
	int ret, cpuid;
	int pid = getpid();
	cpu_set_t mask;
	int thread_id = (int)syscall(__NR_gettid);
	__u32 count = 0;

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	CPU_SET(cpuid, &mask);
	if (cpuid) {
		ret = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);
		if (ret < 0) {
			HPRE_TST_PRT("Proc-%d, thrd-%d:set affinity fail!\n",
						 pid, thread_id);
			return NULL;
		}
		HPRE_TST_PRT("Proc-%d, poll thrd-%d bind to cpu-%d!\n",
					 pid, thread_id, cpuid);
	}

	while (1) {
		ret = wd_dh_poll(0, &count);
		if (ret < 0) {
			break;
		}

		if (asyn_thread_exit)
			break;
	}

	if (g_config.with_log)
		HPRE_TST_PRT("%s exit!\n", __func__);
	return NULL;
}

static int dh_async_test(int thread_num, __u64 lcore_mask,
			 __u64 hcore_mask, enum alg_op_type op_type)
{
	int i, ret, cnt = 0;
	int h_cpuid;
	float speed = 0.0;

	if (_get_one_bits(lcore_mask) > 0)
		cnt =  _get_one_bits(lcore_mask);
	else if (_get_one_bits(lcore_mask) == 0 &&
		 _get_one_bits(hcore_mask) == 0)
		cnt = thread_num;

	/* Create poll thread at first */
	test_thrds_data[0].thread_num = 1;
	test_thrds_data[0].op_type = op_type;
	test_thrds_data[0].cpu_id = 0;
	gettimeofday(&test_thrds_data[0].start_tval, NULL);
	ret = pthread_create(&system_test_thrds[0], NULL,
			     _dh_async_poll_test_thread, &test_thrds_data[0]);
	if (ret) {
		HPRE_TST_PRT("Create poll thread fail!\n");
		return ret;
	}

	for (i = 1; i <= cnt; i++) {
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].cpu_id = _get_cpu_id(i - 1, lcore_mask);
		gettimeofday(&test_thrds_data[i].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i], NULL,
				    _hpre_dh_sys_test_thread, &test_thrds_data[i]);
		if (ret) {
			HPRE_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}

	for (i = 1; i <= thread_num - cnt; i++) {
		h_cpuid = _get_cpu_id(i - 1, hcore_mask);
		if (h_cpuid > 0)
			h_cpuid += 64;

		test_thrds_data[i + cnt].thread_num = thread_num;
		test_thrds_data[i + cnt].op_type = op_type;
		test_thrds_data[i + cnt].cpu_id = h_cpuid;
		gettimeofday(&test_thrds_data[i + cnt].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i + cnt], NULL,
				 _hpre_dh_sys_test_thread, &test_thrds_data[i + cnt]);
		if (ret) {
			HPRE_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}

	for (i = 1; i <= thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			HPRE_TST_PRT("Join %dth thread fail!\n", i);
			return ret;
		}
		speed += test_thrds_data[i].perf;
	}

	asyn_thread_exit = 1;

	ret = pthread_join(system_test_thrds[0], NULL);
	if (ret) {
		HPRE_TST_PRT("Join %dth thread fail!\n", i);
		return ret;
	}

	if (g_config.perf_test)
		HPRE_TST_PRT("<< %s %u thread %s %s mode %u key_bits at %0.3f ops!\n",
			g_config.trd_mode, g_config.trd_num, g_config.op,
			g_config.alg_mode, g_config.key_bits, speed);
	HPRE_TST_PRT("<< test finish!\n");

	return 0;
}

void *_hpre_sys_test_thread(void *data)
{
	enum alg_op_type op_type;
	struct test_hpre_pthread_dt *pdata = data;

	op_type = pdata->op_type;
	if (op_type > MAX_DH_TYPE && op_type < MAX_ECC_TYPE) {
		return _ecc_sys_test_thread(data);
	} else if (op_type > MAX_RSA_ASYNC_TYPE && op_type < MAX_DH_TYPE) {
		return _hpre_dh_sys_test_thread(data);
	} else {
		return _hpre_rsa_sys_test_thread(data);
	}

	return NULL;
}

static void *_ecc_async_poll_test_thread(void *data)
{
	__u32 count = 0;
	__u32 expt = 0;
	int ret = 0;

	while (1) {
		ret = wd_ecc_poll(expt, &count);
		if (ret < 0) {
			break;
		}

		if (asyn_thread_exit)
			break;
	}

	if (g_config.with_log)
		HPRE_TST_PRT("%s exit!\n", __func__);

	return NULL;
}

static int ecc_async_test(int thread_num, __u64 lcore_mask,
			 __u64 hcore_mask, enum alg_op_type op_type)
{
	int i, ret, cnt = 0;
	int h_cpuid;
	float speed = 0.0;

	if (_get_one_bits(lcore_mask) > 0)
		cnt = _get_one_bits(lcore_mask);
	else if (_get_one_bits(lcore_mask) == 0 &&
		 _get_one_bits(hcore_mask) == 0)
		cnt = thread_num;

	/* Create poll thread at first */
	test_thrds_data[0].thread_num = 1;
	test_thrds_data[0].op_type = op_type;
	test_thrds_data[0].cpu_id = 0;
	ret = pthread_create(&system_test_thrds[0], NULL,
			     _ecc_async_poll_test_thread, &test_thrds_data[0]);
	if (ret) {
		HPRE_TST_PRT("Create poll thread fail!\n");
		return ret;
	}

	for (i = 1; i <= cnt; i++) {
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].cpu_id = _get_cpu_id(i - 1, lcore_mask);
		gettimeofday(&test_thrds_data[i].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i], NULL,
				    _ecc_sys_test_thread, &test_thrds_data[i]);
		if (ret) {
			HPRE_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}

	for (i = 1; i <= thread_num - cnt; i++) {
		h_cpuid = _get_cpu_id(i - 1, hcore_mask);
		if (h_cpuid > 0)
			h_cpuid += 64;

		test_thrds_data[i + cnt].thread_num = thread_num;
		test_thrds_data[i + cnt].op_type = op_type;
		test_thrds_data[i + cnt].cpu_id = h_cpuid;
		gettimeofday(&test_thrds_data[i + cnt].start_tval, NULL);
		ret = pthread_create(&system_test_thrds[i + cnt], NULL,
				 _ecc_sys_test_thread, &test_thrds_data[i + cnt]);
		if (ret) {
			HPRE_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}

	for (i = 1; i <= thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			HPRE_TST_PRT("Join %dth thread fail!\n", i);
			return ret;
		}
		speed += test_thrds_data[i].perf;
	}

	asyn_thread_exit = 1;

	ret = pthread_join(system_test_thrds[0], NULL);
	if (ret) {
		HPRE_TST_PRT("Join %dth thread fail!\n", i);
		return ret;
	}

	if (g_config.perf_test)
		HPRE_TST_PRT("<< %s %u thread %s %s mode %u key_bits at %0.3f ops!\n",
			g_config.trd_mode, g_config.trd_num, g_config.op,
			g_config.alg_mode, g_config.key_bits, speed);

	HPRE_TST_PRT("<< test finish!\n");

	return 0;
}

static void print_help(void);
static int parse_cmd_line(int argc, char *argv[])
{
        int option_index = 0;
	int rand_type_set = 0;
	int msg_type_set = 0;
	int id_len_set = 0;
	int hash_type_set = 0;
	int rand_len_set = 0;
        int optind_t;
	int ret = 0;
	int bits;
        int c;

        static struct option long_options[] = {
            {"op",     required_argument, 0,  0 },
            {"mode",  	required_argument, 0,  0 },
            {"dev_path",  required_argument, 0,  0 },
            {"key_bits", required_argument,       0,  0 },
            {"cycles",  required_argument, 0, 0},
            {"seconds",    required_argument, 0,  0 },
            {"log",    required_argument, 0,  0 },
            {"check",    required_argument, 0,  0 },
            {"data_from",    required_argument, 0,  0 },
            {"soft",    no_argument, 0,  0 },
            {"perf",    no_argument, 0,  0 },
            {"use_env",    no_argument, 0,  0 },
            {"trd_mode",    required_argument, 0,  0 },
            {"curve",    required_argument, 0,  0 },
            {"msg_type",    required_argument, 0,  0 },
            {"rand_type",    required_argument, 0,  0 },
            {"hash_type",    required_argument, 0,  0 },
            {"msg_len",    required_argument, 0,  0 },
            {"rand_len",    required_argument, 0,  0 },
            {"id_len",    required_argument, 0,  0 },
            {"help",    no_argument, 0,  'h' },
            {0,         0,                 0,  0 }
        };

        while (1) {
        	optind_t = optind ? optind: 1;

        	c = getopt_long(argc, argv, "t:c:", long_options, &option_index);
        	if (c == -1) {
			if (optind_t < argc) {
				print_help();
				ret = -1;
			}
        		break;
		}

		switch (c) {
		case 0:
			if (!strncmp(long_options[option_index].name, "mode", 4)) {
				snprintf(g_config.alg_mode, sizeof(g_config.alg_mode), "%s", optarg);
			} else if (!strncmp(long_options[option_index].name, "dev_path", 8)) {
				snprintf(g_config.dev_path, sizeof(g_config.dev_path), "%s", optarg);
			} else if (!strncmp(long_options[option_index].name, "key_bits", 8)) {
				g_config.key_bits = strtoul((char *)optarg, NULL, 10);
			} else if (!strncmp(long_options[option_index].name, "cycles", 6)) {
				g_config.times = strtoul((char *)optarg, NULL, 10);
			} else if (!strncmp(long_options[option_index].name, "seconds", 7)) {
				g_config.seconds = strtoul((char *)optarg, NULL, 10);
			} else if (!strncmp(long_options[option_index].name, "curve", 5)) {
				snprintf(g_config.curve, sizeof(g_config.curve), "%s", optarg);
			} else if (!strncmp(long_options[option_index].name, "data_from", 9)) {
				g_config.data_from = strtoul((char *)optarg, NULL, 10);
				if (g_config.data_from != 0 && g_config.data_from != 1) {
					HPRE_TST_PRT("data must set 0 or 1\n");
					return -1;
				}
			} else if (!strncmp(long_options[option_index].name, "log", 3)) {
				if (!strncmp(optarg, "y", 1) || !strncmp(optarg, "Y", 1))
					g_config.with_log = 1;
				else
					g_config.with_log = 0;
			} else if (!strncmp(long_options[option_index].name, "check", 5)) {
				if (!strncmp(optarg, "y", 1) || !strncmp(optarg, "Y", 1)) {
					g_config.check = 1;
				} else {
					g_config.check = 0;
				}
			} else if (!strncmp(long_options[option_index].name, "soft", 4)) {
				g_config.soft_test = 1;
			} else if (!strncmp(long_options[option_index].name, "perf", 4)) {
				g_config.perf_test = 1;
			} else if (!strncmp(long_options[option_index].name, "use_env", 7)) {
				g_config.use_env = 1;
			} else if (!strncmp(long_options[option_index].name, "trd_mode", 8)) {
				snprintf(g_config.trd_mode, sizeof(g_config.trd_mode), "%s", optarg);
			} else if (!strncmp(long_options[option_index].name, "op", 2)) {
				snprintf(g_config.op, sizeof(g_config.op), "%s", optarg);
			} else if (!strncmp(long_options[option_index].name, "msg_type", 8)) {
				if (!strncmp(optarg, "digest", 6))
					g_config.msg_type = MSG_DIGEST;
				else if (!strncmp(optarg, "plaintext", 9))
					g_config.msg_type = MSG_PLAINTEXT;
				msg_type_set = 1;
			} else if (!strncmp(long_options[option_index].name, "msg_len", 7)) {
				g_config.msg_len = strtoul((char *)optarg, NULL, 10);
			} else if (!strncmp(long_options[option_index].name, "id_len", 6)) {
				g_config.id_len = strtoul((char *)optarg, NULL, 10);
				id_len_set = 1;
			} else if (!strncmp(long_options[option_index].name, "rand_type", 9)) {
				if (!strncmp(optarg, "param", 5))
					g_config.rand_type = RAND_PARAM;
				else if (!strncmp(optarg, "cb", 2))
					g_config.rand_type = RAND_CB;
				else if (!strncmp(optarg, "non", 2))
					g_config.rand_type = RAND_NON;
				rand_type_set = 1;
			} else if (!strncmp(long_options[option_index].name, "rand_len", 8)) {
				g_config.k_len = strtoul((char *)optarg, NULL, 10);
				rand_len_set = 1;
			} else if (!strncmp(long_options[option_index].name, "hash_type", 9)) {
				if (!strncmp(optarg, "non", 3))
					g_config.hash_type = HASH_NON;
				else if (!strncmp(optarg, "sm3", 3))
					g_config.hash_type = HASH_SM3;
				else if (!strncmp(optarg, "sha1", 4))
					g_config.hash_type = HASH_SHA1;
				else if (!strncmp(optarg, "sha224", 6))
					g_config.hash_type = HASH_SHA224;
				else if (!strncmp(optarg, "sha256", 6))
					g_config.hash_type = HASH_SHA256;
				else if (!strncmp(optarg, "sha384", 6))
					g_config.hash_type = HASH_SHA384;
				else if (!strncmp(optarg, "sha512", 6))
					g_config.hash_type = HASH_SHA512;
				else if (!strncmp(optarg, "md4", 3))
					g_config.hash_type = HASH_MD4;
				else if (!strncmp(optarg, "md5", 3))
					g_config.hash_type = HASH_MD5;
				hash_type_set = 1;
			}
			break;

		case 't':
			g_config.trd_num = strtoul((char *)optarg, NULL, 10);
			if (g_config.trd_num <= 0 || g_config.trd_num > TEST_MAX_THRD) {
				HPRE_TST_PRT("Invalid threads num:%d!\n",
								g_config.trd_num);
				HPRE_TST_PRT("Now set threads num as 2\n");
				g_config.trd_num = 2;
			}
			break;
		case 'c':
			if (optarg[0] != '0' || optarg[1] != 'x') {
				HPRE_TST_PRT("Err:coremask should be hex!\n");
				return -EINVAL;
			}

			if (strlen(optarg) > 34) {
				HPRE_TST_PRT("warn:coremask is cut!\n");
				optarg[34] = 0;
			}

			if (strlen(optarg) <= 18) {
				g_config.core_mask[0] = strtoull(optarg, NULL, 16);
				if (g_config.core_mask[0] & 0x1) {
					HPRE_TST_PRT("Warn:cannot bind to core 0,\n");
					HPRE_TST_PRT("now run without binding\n");
					g_config.core_mask[0] = 0x0; /* no binding */
				}
				g_config.core_mask[1] = 0;
			} else {
				int offset = 0;
				char *temp;

				offset = strlen(optarg) - 16;
				g_config.core_mask[0] = strtoull(&optarg[offset], NULL, 16);
				if (g_config.core_mask[0] & 0x1) {
					HPRE_TST_PRT("Warn:cannot bind to core 0,\n");
					HPRE_TST_PRT("now run without binding\n");
					g_config.core_mask[0] = 0x0; /* no binding */
				}
				temp = malloc(64);
				strcpy(temp, optarg);
				temp[offset] = 0;
				g_config.core_mask[1] = strtoull(temp, NULL, 16);
				free(temp);
			}
			bits = _get_one_bits(g_config.core_mask[0]);
			bits += _get_one_bits(g_config.core_mask[1]);
			if (g_config.trd_num > bits) {
				HPRE_TST_PRT("Coremask not covers all thrds,\n");
				HPRE_TST_PRT("Bind first %d thrds!\n", bits);
			} else if (g_config.trd_num < bits) {
				HPRE_TST_PRT("Coremask overflow,\n");
				HPRE_TST_PRT("Just try to bind all thrds!\n");
			};
			break;

		case '?':
		case 'h':
			print_help();
			ret = -1;
		    break;

		default:
		    printf("?? getopt returned character code 0%o ??\n", c);
		    break;
		}
	}

	if (g_config.perf_test)
		g_config.data_from = 1;

	if (!strncmp(g_config.op, "sm2-verf", 8) && g_config.msg_type != MSG_PLAINTEXT) {
		g_config.msg_type = MSG_PLAINTEXT;
		HPRE_TST_PRT("message only support plantext!\n");
	} else if (g_config.data_from && (!strncmp(g_config.op, "sm2-sign", 8) || !strncmp(g_config.op, "sm2-verf", 8))) {
		g_config.msg_type = MSG_DIGEST;
	}

	if (g_config.data_from &&
		(rand_type_set || msg_type_set || id_len_set || rand_len_set || hash_type_set))
		HPRE_TST_PRT("The algorithm input parameters comes from samples, do not config it!\n");

	return ret;
}

int main(int argc, char *argv[])
{
	enum alg_op_type alg_op_type = HPRE_ALG_INVLD_TYPE;
	int ret = 0;

	ret = parse_cmd_line(argc, argv);
	if (ret)
		return -1;

	if (!strcmp(g_config.op, "rsa-gen")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = RSA_ASYNC_GEN;
		else
			alg_op_type = RSA_KEY_GEN;
	} else if (!strcmp(g_config.op, "rsa-vrf")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = RSA_ASYNC_EN;
		else
			alg_op_type = RSA_PUB_EN;
	} else if (!strcmp(g_config.op, "rsa-sgn")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = RSA_ASYNC_DE;
		else
			alg_op_type = RSA_PRV_DE;
	} else if (!strcmp(g_config.op, "dh-gen1")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = DH_ASYNC_GEN;
		else
			alg_op_type = DH_GEN;
	} else if (!strcmp(g_config.op, "dh-gen2")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = DH_ASYNC_COMPUTE;
		else
			alg_op_type = DH_COMPUTE;
	} else if (!strcmp(g_config.op, "ecdh-gen1")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = ECDH_ASYNC_GEN;
		else
			alg_op_type = ECDH_GEN;
	} else if (!strcmp(g_config.op, "ecdh-gen2")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = ECDH_ASYNC_COMPUTE;
		else
			alg_op_type = ECDH_COMPUTE;
	} else if (!strcmp(g_config.op, "ecdsa-sign")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = ECDSA_ASYNC_SIGN;
		else
			alg_op_type = ECDSA_SIGN;
	} else if (!strcmp(g_config.op, "ecdsa-verf")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = ECDSA_ASYNC_VERF;
		else
			alg_op_type = ECDSA_VERF;
	} else if (!strcmp(g_config.op, "x25519-gen1")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = X25519_ASYNC_GEN;
		else
			alg_op_type = X25519_GEN;
	} else if (!strcmp(g_config.op, "x25519-gen2")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = X25519_ASYNC_COMPUTE;
		else
			alg_op_type = X25519_COMPUTE;
	} else if (!strcmp(g_config.op, "x448-gen1")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = X448_ASYNC_GEN;
		else
			alg_op_type = X448_GEN;
	} else if (!strcmp(g_config.op, "x448-gen2")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = X448_ASYNC_COMPUTE;
		else
			alg_op_type = X448_COMPUTE;
	} else if (!strcmp(g_config.op, "sm2-sign")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = SM2_ASYNC_SIGN;
		else
			alg_op_type = SM2_SIGN;
	} else if (!strcmp(g_config.op, "sm2-verf")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = SM2_ASYNC_VERF;
		else
			alg_op_type = SM2_VERF;
	} else if (!strcmp(g_config.op, "sm2-enc")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = SM2_ASYNC_ENC;
		else
			alg_op_type = SM2_ENC;
	} else if (!strcmp(g_config.op, "sm2-dec")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = SM2_ASYNC_DEC;
		else
			alg_op_type = SM2_DEC;
	} else if (!strcmp(g_config.op, "sm2-kg")) {
		if (!strcmp(g_config.trd_mode, "async"))
			alg_op_type = SM2_ASYNC_KG;
		else
			alg_op_type = SM2_KG;
	} else {
	}

	if ((alg_op_type >= X25519_GEN && alg_op_type <= X25519_ASYNC_COMPUTE) ||
		!strncmp(g_config.op, "sm2", 3))
		g_config.key_bits = 256;
	else if (alg_op_type >= X448_GEN && alg_op_type <= X448_ASYNC_COMPUTE)
		g_config.key_bits = 448;

  	ret = init_hpre_global_config(alg_op_type);
  	if (ret) {
  		HPRE_TST_PRT("failed to init_hpre_global_config, ret %d!\n", ret);
  		return -1;
  	}

	HPRE_TST_PRT(">> test start run %s :\n", g_config.op);
	HPRE_TST_PRT(">> key_bits = %u\n", g_config.key_bits);
	HPRE_TST_PRT(">> trd_mode = %s\n", g_config.trd_mode);
	HPRE_TST_PRT(">> trd_num = %u\n", g_config.trd_num);
	HPRE_TST_PRT(">> core_mask = [0x%llx][0x%llx]\n", g_config.core_mask[1],
		g_config.core_mask[0]);
	HPRE_TST_PRT(">> msg_type = %u\n", g_config.msg_type);
	HPRE_TST_PRT(">> msg_len = 0x%x\n", g_config.msg_len);
	HPRE_TST_PRT(">> id_len = 0x%x\n", g_config.id_len);
	HPRE_TST_PRT(">> hash_type = %u\n", g_config.hash_type);
	HPRE_TST_PRT(">> rand_type = %u\n", g_config.rand_type);
	HPRE_TST_PRT(">> rand_len = 0x%x\n", g_config.k_len);
	HPRE_TST_PRT(">> data_from = %u\n", g_config.data_from);
	HPRE_TST_PRT(">> perf_test = %u\n", g_config.perf_test);
	HPRE_TST_PRT(">> check = %u\n", g_config.check);
	HPRE_TST_PRT(">> cycles = %u\n", g_config.times);
	HPRE_TST_PRT(">> seconds = %u\n", g_config.seconds);

	if (g_config.perf_test)
		HPRE_TST_PRT("performance test did not verify output!\n");

	if (alg_op_type < MAX_RSA_SYNC_TYPE ||
		alg_op_type == DH_GEN || alg_op_type == DH_COMPUTE ||
		alg_op_type == ECDH_GEN || alg_op_type == ECDH_COMPUTE ||
		alg_op_type == ECDSA_SIGN || alg_op_type == ECDSA_VERF ||
		alg_op_type == X25519_GEN || alg_op_type == X25519_COMPUTE ||
		alg_op_type == X448_GEN || alg_op_type == X448_COMPUTE ||
		alg_op_type == SM2_SIGN || alg_op_type == SM2_VERF ||
		alg_op_type == SM2_ENC || alg_op_type == SM2_DEC ||
		alg_op_type == SM2_KG)
			ret = hpre_sys_test(g_config.trd_num, g_config.core_mask[0],
				g_config.core_mask[1], alg_op_type, g_config.dev_path, 0);
	else if (alg_op_type > MAX_RSA_SYNC_TYPE && alg_op_type < MAX_RSA_ASYNC_TYPE)
		ret = rsa_async_test(g_config.trd_num, g_config.core_mask[0],
			g_config.core_mask[1], alg_op_type);
	else if (alg_op_type == DH_ASYNC_GEN || alg_op_type == DH_ASYNC_COMPUTE)
		ret = dh_async_test(g_config.trd_num, g_config.core_mask[0],
					      g_config.core_mask[1], alg_op_type);
	else if (alg_op_type == ECDH_ASYNC_GEN || alg_op_type == ECDH_ASYNC_COMPUTE ||
		alg_op_type == ECDSA_ASYNC_SIGN || alg_op_type == ECDSA_ASYNC_VERF ||
		alg_op_type == X25519_ASYNC_GEN || alg_op_type == X25519_ASYNC_COMPUTE ||
		alg_op_type == X448_ASYNC_GEN || alg_op_type == X448_ASYNC_COMPUTE ||
		alg_op_type == SM2_ASYNC_SIGN || alg_op_type == SM2_ASYNC_VERF ||
		alg_op_type == SM2_ASYNC_ENC || alg_op_type == SM2_ASYNC_DEC ||
		alg_op_type == SM2_ASYNC_KG)
		return ecc_async_test(g_config.trd_num, g_config.core_mask[0],
					g_config.core_mask[1], alg_op_type);
	else
		ret = -1; /* to extend other test samples */

	uninit_hpre_global_config(alg_op_type);

	return ret;

}

static void print_help(void)
{
	HPRE_TST_PRT("UPDATE:2021-02-01\n");
	HPRE_TST_PRT("NAME\n");
	HPRE_TST_PRT("    test_hisi_hpre: test wd hpre function,etc\n");
	HPRE_TST_PRT("USAGE\n");
	HPRE_TST_PRT("    test_hisi_hpre [--op=] [-t] [-c] [--mode=] [--help]\n");
	HPRE_TST_PRT("    test_hisi_hpre [--dev_path=] [--curve=] [--key_bits=]\n");
	HPRE_TST_PRT("    test_hisi_hpre [--seconds=] [--times=] [--trd_mode=]\n");
	HPRE_TST_PRT("    test_hisi_hpre [--msg_type=] [--msg_len=] [--id_len=]\n");
	HPRE_TST_PRT("    test_hisi_hpre [--rand_type=] [--rand_len=] [--hash_type=]\n");
	HPRE_TST_PRT("DESCRIPTION\n");
	HPRE_TST_PRT("    [--op=]:\n");
	HPRE_TST_PRT("        rsa-gen  = RSA key generate test\n");
	HPRE_TST_PRT("        rsa-sgn  = RSA signature test\n");
	HPRE_TST_PRT("        rsa-vrf  = RSA verification test\n");
	HPRE_TST_PRT("        dh-gen1  = DH phase 1 key generate test\n");
	HPRE_TST_PRT("        dh-gen2  = DH phase 2 key generate test\n");
	HPRE_TST_PRT("        ecdh-gen1  = ECDH phase 1 key generate test\n");
	HPRE_TST_PRT("        ecdh-gen2  = ECDH phase 2 key generate test\n");
	HPRE_TST_PRT("        sm2-sign  = SM2 sign test\n");
	HPRE_TST_PRT("        sm2-verf  = SM2 verify test\n");
	HPRE_TST_PRT("        sm2-enc  = SM2 encrypt test\n");
	HPRE_TST_PRT("        sm2-dec  = SM2 decrypt test\n");
	HPRE_TST_PRT("        sm2-kg  = SM2 key generate test\n");
	HPRE_TST_PRT("    [-t]: start thread total\n");
	HPRE_TST_PRT("    [-c]: mask for bind cpu core, as 0x3 bind to cpu-1 and cpu-2\n");
	HPRE_TST_PRT("    [--log=]:\n");
	HPRE_TST_PRT("        y\n");
	HPRE_TST_PRT("        n\n");
	HPRE_TST_PRT("    [--perf]: use test algorithm perf\n");
	HPRE_TST_PRT("    [--check=]:\n");
	HPRE_TST_PRT("        y: check result compared with openssl\n");
	HPRE_TST_PRT("        n: no check\n");
	HPRE_TST_PRT("    [--key_bits=]:key size (bits)\n");
	HPRE_TST_PRT("    [--mode=]: used by DH/RSA\n");
	HPRE_TST_PRT("        g2  = DH G2 mode\n");
	HPRE_TST_PRT("        com  = common mode\n");
	HPRE_TST_PRT("        crt  = RSA CRT mode\n");
	HPRE_TST_PRT("    [--trd_mode=]:\n");
	HPRE_TST_PRT("        sync  = synchronize test\n");
	HPRE_TST_PRT("        async  = asynchronize test\n");
	HPRE_TST_PRT("    [--curve=]: used by ECDH/ECDSA\n");
	HPRE_TST_PRT("        secp128R1  = 128 bit\n");
	HPRE_TST_PRT("        secp192K1  = 192 bit\n");
	HPRE_TST_PRT("        secp224R1  = 224 bit\n");
	HPRE_TST_PRT("        secp256K1  = 256bit\n");
	HPRE_TST_PRT("        brainpoolP320R1  = 320bit\n");
	HPRE_TST_PRT("        secp384R1  = 384bit\n");
	HPRE_TST_PRT("        secp521R1  = 521bit\n");
	HPRE_TST_PRT("        null  = by set parameters\n");
	HPRE_TST_PRT("    [--msg_type=]: used by SM2\n");
	HPRE_TST_PRT("        digest  = hash value\n");
	HPRE_TST_PRT("        plaintext\n");
	HPRE_TST_PRT("    [--msg_len=]: used by SM2, default size base on sample data\n");
	HPRE_TST_PRT("    [--rand_type=]: used by SM2\n");
	HPRE_TST_PRT("        param  = from user input param\n");
	HPRE_TST_PRT("        cb  = from user callback\n");
	HPRE_TST_PRT("        non  = both not config\n");
	HPRE_TST_PRT("    [--rand_len=]: used by SM2, default size base on sample data\n");
	HPRE_TST_PRT("    [--id_len=]: used by SM2, default size base on sample data\n");
	HPRE_TST_PRT("    [--hash_type=]: used by SM2, default SM3\n");
	HPRE_TST_PRT("        sha1/sha224/sha256/sha384/sha512/md4/md5\n");
	HPRE_TST_PRT("    [--data_from=]: 0 - from openssl, 1 - from sample data\n");
	HPRE_TST_PRT("    [--dev_path=]: designed dev path\n");
	HPRE_TST_PRT("    [--seconds=]: test time set (s)\n");
	HPRE_TST_PRT("    [--cycles=]: test cycle set (times)\n");
	HPRE_TST_PRT("    [--help]  = usage\n");
}

