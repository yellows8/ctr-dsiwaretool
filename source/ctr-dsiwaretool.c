#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include "ec.h"

typedef struct ecc_point_t//These ecc_point_t and ecc_cert_t structs are from save_adjust.
{
	uint8_t r[0x1e];
	uint8_t s[0x1e];
} __attribute__((packed)) ecc_point_t;

typedef struct ecc_cert_t
{
	struct {
		uint32_t type;
		ecc_point_t val;
		uint8_t padding[0x40];
	} sig;
	char issuer[0x40];
	uint32_t key_type;
	char key_id[0x40];
	uint32_t unk;
	ecc_point_t pubkey;
	uint8_t padding2[0x3c];
} __attribute__((packed)) ecc_cert_t;

int verifyecdsa_signature(ecc_point_t *certpubkeypoint, ecc_point_t *signature, uint8_t *hash, uint32_t hashsize)
{
	int ret;
	BIGNUM *pubkey_x_bn = BN_new();
	BIGNUM *pubkey_y_bn = BN_new();

	BN_bin2bn(certpubkeypoint->r, sizeof(certpubkeypoint->r), pubkey_x_bn);
	BN_bin2bn(certpubkeypoint->s, sizeof(certpubkeypoint->s), pubkey_y_bn);
 
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sect233r1);
	EC_POINT *pubkey_pt = EC_POINT_new(group);

	EC_POINT_set_affine_coordinates_GF2m(group, pubkey_pt, pubkey_x_bn, pubkey_y_bn, NULL);
	
	EC_KEY *cert_pubkey = EC_KEY_new_by_curve_name(NID_sect233r1);
	EC_KEY_set_public_key(cert_pubkey, pubkey_pt);

	ECDSA_SIG sig;
	sig.r = BN_new();
	BN_bin2bn(signature->r, sizeof(signature->r), sig.r);
	sig.s = BN_new();
	BN_bin2bn(signature->s, sizeof(signature->s), sig.s);
	
	ret = ECDSA_do_verify(hash, hashsize, &sig, cert_pubkey);

	EC_KEY_free(cert_pubkey);
	EC_POINT_free(pubkey_pt);
	EC_GROUP_free(group);
	BN_clear_free(pubkey_x_bn);
	BN_clear_free(pubkey_y_bn);
	BN_clear_free(sig.r);
	BN_clear_free(sig.s);

	return ret;
}

void create_ecdsa_signature(uint8_t *privkey, uint8_t *hash, uint32_t hashsize, ecc_point_t *signature_out)
{
	BIGNUM *ct_privkey_bn = BN_bin2bn(privkey, 30, NULL);
	EC_KEY *ct_privkey = EC_KEY_new_by_curve_name(NID_sect233r1);
	EC_KEY_set_private_key(ct_privkey, ct_privkey_bn);

	
	ECDSA_SIG *sig = ECDSA_do_sign(hash, hashsize, ct_privkey);
	memset(signature_out->r, 0, sizeof(signature_out->r));
	BN_bn2bin(sig->r, &signature_out->r[sizeof(signature_out->r)-((BN_num_bits(sig->r)+7)/8)]);
	memset(signature_out->s, 0, sizeof(signature_out->s));
	BN_bn2bin(sig->s, &signature_out->s[sizeof(signature_out->s)-((BN_num_bits(sig->s)+7)/8)]);

	ECDSA_SIG_free(sig);
	EC_KEY_free(ct_privkey);
	BN_clear_free(ct_privkey_bn);
}

void generate_ecdsakeys(ecc_point_t *certpubkey, uint8_t *privkey)
{
	FILE *f;
	BIGNUM *x, *y;
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sect233r1);
	EC_POINT *pubkey = EC_POINT_new(group);
	BIGNUM *privkey_bn;

	f = fopen("/dev/random", "rb");
	fread(privkey, 1, 30, f);
	fclose(f);
	privkey[0] &= 1;

	privkey_bn = BN_bin2bn(privkey, 30, NULL);
	EC_POINT_mul(group, pubkey, privkey_bn, NULL, NULL, NULL);

	x = BN_new();
	y = BN_new();

	EC_POINT_get_affine_coordinates_GF2m(group, pubkey, x, y, NULL);

	BN_bn2bin(x, certpubkey->r);
	BN_bn2bin(y, certpubkey->s);

	memset(certpubkey->r, 0, sizeof(certpubkey->r));
	BN_bn2bin(x, &certpubkey->r[sizeof(certpubkey->r)-((BN_num_bits(x)+7)/8)]);
	memset(certpubkey->s, 0, sizeof(certpubkey->s));
	BN_bn2bin(y, &certpubkey->s[sizeof(certpubkey->s)-((BN_num_bits(y)+7)/8)]);

	EC_POINT_free(pubkey);
	EC_GROUP_free(group);
	BN_clear_free(x);
	BN_clear_free(y);
	BN_clear_free(privkey_bn);
}

int verify_footer(unsigned char *footer, unsigned int totalhashsize)
{
	int ret=0;
	unsigned char *hashblock = footer;
	ecc_point_t *signature = (ecc_point_t*)&footer[totalhashsize];
	ecc_cert_t *apcert = (ecc_cert_t*)&footer[totalhashsize + 0x3c];
	ecc_cert_t *ctcert = (ecc_cert_t*)&footer[totalhashsize + 0x1bc];
	unsigned char tmphash[32];

	printf("totalhashsize %x\n", totalhashsize);

	memset(tmphash, 0, 32);
	SHA256(hashblock, totalhashsize, tmphash);
	ret = verifyecdsa_signature(&apcert->pubkey, signature, tmphash, 0x20);
	if(ret==1)
	{
		printf("Footer signature over the hash block is valid.\n");
	}
	else
	{
		printf("Footer signature over the hash block is invalid.\n");
		return 1;
	}

	SHA256((uint8_t*)apcert->issuer, sizeof(ecc_cert_t) - sizeof(apcert->sig), tmphash);
	ret = verifyecdsa_signature(&ctcert->pubkey, &apcert->sig.val, tmphash, 0x20);
	if(ret==1)
	{
		printf("APCert signature is valid.\n");
	}
	else
	{
		printf("APCert signature is invalid.\n");
		return 1;
	}

	return 0;
}

void sign_footer(unsigned char *footer, unsigned int totalhashsize, unsigned char *sign_ctcert)
{
	unsigned char *hashblock = footer;
	ecc_point_t *signature = (ecc_point_t*)&footer[totalhashsize];
	ecc_cert_t *apcert = (ecc_cert_t*)&footer[totalhashsize + 0x3c];
	ecc_cert_t *ctcert = (ecc_cert_t*)&footer[totalhashsize + 0x1bc];

	unsigned char tmphash[32];
	uint8_t apcert_privk[30];

	generate_ecdsakeys(&apcert->pubkey, apcert_privk);

	printf("Signing footer signature... ");
	SHA256(hashblock, totalhashsize, tmphash);
	create_ecdsa_signature(apcert_privk, tmphash, 0x20, signature);
	printf("Done.\n");

	memcpy(ctcert, sign_ctcert, sizeof(ecc_cert_t));

	memset(apcert->issuer, 0, 0x40);
	snprintf(apcert->issuer, 0x40, "%s-%s", ctcert->issuer, ctcert->key_id);

	printf("Signing APCert... ");
	SHA256((uint8_t*)apcert->issuer, sizeof(ecc_cert_t) - sizeof(apcert->sig), tmphash);
	create_ecdsa_signature(&sign_ctcert[0x180], tmphash, 0x20, &apcert->sig.val);
	printf("Done.\n");
}

int main(int argc, char **argv)
{
	FILE *f;
	unsigned int totalhashsize = 0;
	struct stat filestat;
	unsigned char footer[0x4e0];
	unsigned char sign_ctcert[0x19e];

	if(argc<2)return 0;

	if(stat(argv[1], &filestat)==-1)return 0;

	if((filestat.st_size < 0x400) || (filestat.st_size > 0x4e0))
	{
		printf("Invalid footer.\n");
	}

	memset(footer, 0, 0x4e0);
	memset(sign_ctcert, 0, 0x19e);
	f = fopen(argv[1], "rb");
	if(f==NULL)return 0;
	fread(footer, 1, filestat.st_size, f);
	fclose(f);

	totalhashsize = filestat.st_size - 0x340;

	if(argc>=3)
	{
		printf("Loading CTCert...\n");

		f = fopen(argv[2], "rb");
		if(f==NULL)return 0;
		fread(sign_ctcert, 1, 0x19e, f);
		fclose(f);

		sign_footer(footer, totalhashsize, sign_ctcert);
	}

	if(verify_footer(footer, totalhashsize)!=0)return 1;

	if(argc>=4 && strncmp(argv[3], "--write", 7)==0)
	{
		printf("Writing footer data... ");
		f = fopen(argv[1], "wb");
		if(f==NULL)return 0;
		fwrite(footer, 1, filestat.st_size, f);
		fclose(f);
		printf("Done.\n");
	}

	return 0;
}

