#ifndef CRYPTOCORE_H
#define CRYPTOCORE_H

#include <string>

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPTOCORE_API __attribute__((visibility("default")))

CRYPTOCORE_API std::string affine_encrypt(const std::string& plaintext, int a, int b);
CRYPTOCORE_API std::string affine_decrypt(const std::string& ciphertext, int a, int b);

CRYPTOCORE_API std::string rc4_encrypt(const std::string& plaintext, const std::string& key);
CRYPTOCORE_API std::string rc4_decrypt(const std::string& ciphertext, const std::string& key);

CRYPTOCORE_API std::string lfsr_jk_encrypt(const std::string& plaintext, unsigned int seed);
CRYPTOCORE_API std::string lfsr_jk_decrypt(const std::string& ciphertext, unsigned int seed);

CRYPTOCORE_API std::string des_encrypt(const std::string& plaintext, const std::string& key);
CRYPTOCORE_API std::string des_decrypt(const std::string& ciphertext, const std::string& key);

CRYPTOCORE_API void rsa_generate_keys(int& p, int& q, int& e, int& d, int& n);
CRYPTOCORE_API std::string rsa_encrypt(const std::string& plaintext, int e, int n);
CRYPTOCORE_API std::string rsa_decrypt(const std::string& ciphertext, int d, int n);
CRYPTOCORE_API std::string rsa_decrypt_with_public(const std::string& ciphertext, int e, int n);

CRYPTOCORE_API std::string compute_sha1(const std::string& message);
CRYPTOCORE_API std::string compute_md5(const std::string& message);

CRYPTOCORE_API std::string rsa_sign(const std::string& hash, int d, int n);
CRYPTOCORE_API bool rsa_verify(const std::string& hash, const std::string& signature, int e, int n);

CRYPTOCORE_API int mod_exp(int base, int exp, int mod);

#ifdef __cplusplus
}
#endif

#endif