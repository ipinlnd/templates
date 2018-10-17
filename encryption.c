#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/conf.h>

char* keys[1] = { "7e457d8a9ef375864a49ae5c700aec93" };
char* algo[1] = { "aes" };

int
encrypt(char* input, char* output)
{
	int key_index = 2;
	int algo_index = 3;
	int key_size;
	const EVP_CIPHER *algorithm = EVP_aes_256_cbc();
	const unsigned char* key_string = keys[0];
	size_t key_string_len = strlen(key_string);
	int iteration_count = 5;
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	EVP_CIPHER_CTX *ctx;
	unsigned char *cipher = malloc(strlen(input) * 2);
	int cipher_len, final_len;
	int err = 0;
	char *cipher_result = malloc(strlen(output));
	
	key_size = EVP_BytesToKey(algorithm, EVP_sha1(), NULL, 
							  key_string, key_string_len, 
							  iteration_count, key, iv);
	if (!key_size) {
		err = 1;
		goto end;
	}
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(ctx, algorithm, key, iv);
	EVP_EncryptUpdate(ctx, cipher, &cipher_len, input, strlen(input));
	EVP_EncryptFinal(ctx, cipher + cipher_len, &final_len);
	
	/*TODO: base64 cipher */
	snprintf(cipher_result, cipher_len + final_len + 1, "$%d$%d$%s", algo_index, key_index, cipher);
	
	/* TODO: base64 cipher_result */
	snprintf(output, strlen(cipher_result) - 1, "%s", cipher_result);
end:
	free(cipher);
	free(cipher_result);
	return 0;
}

int
decrypt(char* input, char* output)
{
	int key_index = 0;
	int algo_index = 0;
	int key_size;
	const EVP_CIPHER *algorithm = EVP_aes_256_cbc();
	const unsigned char* key_string = keys[0];
	size_t key_string_len = strlen(key_string);
	int iteration_count = 5;
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	EVP_CIPHER_CTX *ctx;
	unsigned char *cipher = malloc((strlen(input) / 2) + 1);
	int cipher_len, final_len;
	int err = 0;
	char *input_string = malloc(strlen(input));
	
	/* TODO: base64 Decode input*/
	sscanf(input, "$%d$%d$%*s", &algo_index, &key_index);
	memcpy(input_string, input + 5, strlen(input) - 5);
	
	key_size = EVP_BytesToKey(algorithm, EVP_sha1(), NULL, 
							  key_string, key_string_len, 
							  iteration_count, key, iv);
	if (!key_size) {
		err = 1;
		goto end;
	}
	
	/* TODO: base64 decode input_string */
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(ctx, algorithm, key, iv);
	EVP_DecryptUpdate(ctx, cipher, &cipher_len, input_string, strlen(input_string));
	EVP_DecryptFinal(ctx, cipher + cipher_len, &final_len);
	
	snprintf(output, cipher_len + final_len + 1, "%s", cipher);
	
end:
	free(cipher);
	free(input_string);
	return 0;
}

int main(int argc, char **argv)
{
	char *input = argv[1];
	char* output = malloc (strlen(input) * 2);
	char* decrypted = malloc(strlen(input));
	printf("original: %s\n", input);
	encrypt(input, output);
	printf("encrypted: %s\n", output);
	decrypt(output, decrypted);
	printf("decrypted: %s\n", decrypted);
	
	free(output);
	free(decrypted);
	return 0;
}
