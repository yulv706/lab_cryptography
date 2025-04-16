#ifndef CRYPTOCORE_H
#define CRYPTOCORE_H

#include <string>

#ifdef __cplusplus
extern "C" {
#endif

// Function declarations with visibility attribute
#define CRYPTOCORE_API __attribute__((visibility("default")))

// Affine Cipher
CRYPTOCORE_API std::string affine_encrypt(const std::string& plaintext, int a, int b);
CRYPTOCORE_API std::string affine_decrypt(const std::string& ciphertext, int a, int b);

// Stream Cipher: RC4
CRYPTOCORE_API std::string rc4_encrypt(const std::string& plaintext, const std::string& key);
CRYPTOCORE_API std::string rc4_decrypt(const std::string& ciphertext, const std::string& key);

// Stream Cipher: LFSR + J-K Flip-Flop
CRYPTOCORE_API std::string lfsr_jk_encrypt(const std::string& plaintext, unsigned int seed);
CRYPTOCORE_API std::string lfsr_jk_decrypt(const std::string& ciphertext, unsigned int seed);

// DES Encryption
CRYPTOCORE_API std::string des_encrypt(const std::string& plaintext, const std::string& key);
CRYPTOCORE_API std::string des_decrypt(const std::string& ciphertext, const std::string& key);

// RSA Encryption
CRYPTOCORE_API void rsa_generate_keys(int& p, int& q, int& e, int& d, int& n);
CRYPTOCORE_API std::string rsa_encrypt(const std::string& plaintext, int e, int n);
CRYPTOCORE_API std::string rsa_decrypt(const std::string& ciphertext, int d, int n);

// Hash Function: SHA-1
CRYPTOCORE_API std::string compute_sha1(const std::string& message);

// Digital Signatures: RSA
CRYPTOCORE_API std::string rsa_sign(const std::string& hash, int d, int n);
CRYPTOCORE_API bool rsa_verify(const std::string& hash, const std::string& signature, int e, int n);

// Utility for D-H
CRYPTOCORE_API int mod_exp(int base, int exp, int mod);

#ifdef __cplusplus
}
#endif

#endif