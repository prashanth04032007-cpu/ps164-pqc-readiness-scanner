#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/md5.h>

void legacy_crypto_demo() {
    // Vulnerable RSA key generation
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    
    // Legacy MD5 Hash
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)"sample", 6, digest);
    
    // Insecure AES ECB mode
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, NULL, NULL);
}

void quantum_safe_demo() {
    // Quantum safe SHA-3
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
}