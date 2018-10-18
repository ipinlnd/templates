#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/conf.h>

char* keys[1] = { "7e457d8a9ef375864a49ae5c700aec93" };
char* algo[1] = { "aes" };

char*
base64_encode(char* input)
{
	char *encoded_data = malloc(100);
	
	EVP_EncodeBlock(encoded_data, input, strlen(input));
	
	return encoded_data;
}

char*
base64_decode(char* input)
{
	char *decoded_data = malloc(100);
	char padding[] = "=";
	char *padded_input = malloc(strlen(input) + 3);
	int pad;
	int i;
	
	pad = strlen(input) % 4;	
	strcpy(padded_input, input);
	
	for (i = 0; i < pad; i++)
		strncat(padded_input, padding, 1);
	
	EVP_DecodeBlock(decoded_data, padded_input, strlen(padded_input));
	
	free(padded_input);
	return decoded_data;
}

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
	char *encoded_cipher;
	
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
	
	snprintf(cipher_result, cipher_len + final_len + 1, "$%d$%d$%s", algo_index, key_index, cipher);
	
	encoded_cipher = base64_encode(cipher_result);
	snprintf(output, strlen(encoded_cipher) - 1, "%s", encoded_cipher);
end:
	free(cipher);
	free(cipher_result);
	free(encoded_cipher);
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
	char *decoded_input;
	
	/* TODO: base64 Decode input*/
	decoded_input = base64_decode(input);
	sscanf(decoded_input, "$%d$%d$%*s", &algo_index, &key_index);
	memcpy(input_string, decoded_input + 5, strlen(decoded_input) - 5);
	
	key_size = EVP_BytesToKey(algorithm, EVP_sha1(), NULL, 
							  key_string, key_string_len, 
							  iteration_count, key, iv);
	if (!key_size) {
		err = 1;
		goto end;
	}
	
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(ctx, algorithm, key, iv);
	EVP_DecryptUpdate(ctx, cipher, &cipher_len, input_string, strlen(input_string));
	EVP_DecryptFinal(ctx, cipher + cipher_len, &final_len);
	
	snprintf(output, cipher_len + final_len + 1, "%s", cipher);
	
end:
	free(cipher);
	free(input_string);
	free(decoded_input);
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
