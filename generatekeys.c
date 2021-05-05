#include <secp256k1.h>
#include <stdio.h>

static secp256k1_context *ctx = NULL;

int main()
{
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	unsigned char secret[32];

	FILE* frand = fopen("/dev/urandom", "r");
	fread(secret, 32, 1, frand);
	fclose(frand);

	printf("Generated new private key: ");
	for(int i = 0; i < 32; i++)
	{
		printf("%02X", secret[i]);
	}
	printf("\n");

	if(!secp256k1_ec_seckey_verify(ctx, secret))
	{
		printf("Invalid secret key! You are the luckiest human alive probably.\n");
		return 1;
	}

	secp256k1_pubkey public;
	secp256k1_ec_pubkey_create(ctx, &public, secret);
	
	size_t pk_len = 65;
 	unsigned char pk_bytes[34];
	secp256k1_ec_pubkey_serialize(ctx, pk_bytes, &pk_len, &public, SECP256K1_EC_UNCOMPRESSED);
	printf("Public Key: ");
	for(int i = 0; i < pk_len; i++)
	{	
		printf("%02X", pk_bytes[i]);	
	}
	printf("\n");
}
