#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "CryptoCore.h"
#include <iostream>
#include <cryptopp/arc4.h>
#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>

// 工具函数：模逆运算
int mod_inverse(int a, int m) {
    int m0 = m, t, q;
    int x0 = 0, x1 = 1;
    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0) x1 += m0;
    return x1;
}

// 工具函数：模幂运算
int mod_exp(int base, int exp, int mod) {
    int result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

// 仿射密码加密
std::string affine_encrypt(const std::string& plaintext, int a, int b) {
    std::string ciphertext;
    for (char c : plaintext) {
        if (isalpha(c)) {
            int x = toupper(c) - 'A';
            int encrypted = (a * x + b) % 26;
            ciphertext += 'A' + encrypted;
        } else {
            ciphertext += c;
        }
    }
    return ciphertext;
}

// 仿射密码解密
std::string affine_decrypt(const std::string& ciphertext, int a, int b) {
    std::string plaintext;
    int a_inv = mod_inverse(a, 26);
    for (char c : ciphertext) {
        if (isalpha(c)) {
            int y = toupper(c) - 'A';
            int decrypted = (a_inv * (y - b + 26)) % 26;
            plaintext += 'A' + decrypted;
        } else {
            plaintext += c;
        }
    }
    return plaintext;
}

// RC4 流密码加密
std::string rc4_encrypt(const std::string& plaintext, const std::string& key) {
    try {
        std::string ciphertext(plaintext.size(), 0);
        CryptoPP::Weak::ARC4 rc4((const CryptoPP::byte*)key.data(), key.size());
        rc4.ProcessData((CryptoPP::byte*)ciphertext.data(), (const CryptoPP::byte*)plaintext.data(), plaintext.size());
        return ciphertext;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "RC4 encryption error: " << e.what() << std::endl;
        throw std::runtime_error("RC4 encryption failed");
    }
}

// RC4 流密码解密（对称）
std::string rc4_decrypt(const std::string& ciphertext, const std::string& key) {
    return rc4_encrypt(ciphertext, key); // RC4 是对称的
}

// LFSR + J-K 触发器流密码
class LFSR {
private:
    unsigned int state;
public:
    LFSR(unsigned int seed) : state(seed & 0xF) {}
    unsigned int get_state() { return state; }
    void clock() {
        bool bit0 = state & 1;
        bool bit3 = (state >> 3) & 1;
        bool feedback = bit0 ^ bit3;
        state = ((state << 1) & 0xF) | feedback;
    }
};

class JKFlipFlop {
private:
    bool q;
public:
    JKFlipFlop() : q(false) {}
    void clock(bool j, bool k) {
        if (j && k) q = !q;
        else if (j) q = true;
        else if (k) q = false;
    }
    bool get_output() { return q; }
};

std::string lfsr_jk_encrypt(const std::string& plaintext, unsigned int seed) {
    LFSR lfsr(seed);
    JKFlipFlop jk;
    std::string ciphertext = plaintext;
    for (char& c : ciphertext) {
        unsigned char key_byte = 0;
        for (int i = 0; i < 8; ++i) {
            lfsr.clock();
            unsigned int state = lfsr.get_state();
            bool j = state & 1;
            bool k = (state >> 1) & 1;
            jk.clock(j, k);
            key_byte |= (jk.get_output() << i);
        }
        c ^= key_byte;
    }
    return ciphertext;
}

std::string lfsr_jk_decrypt(const std::string& ciphertext, unsigned int seed) {
    return lfsr_jk_encrypt(ciphertext, seed); // 对称
}

// DES 加密
std::string des_encrypt(const std::string& plaintext, const std::string& key) {
    try {
        std::string ciphertext;
        CryptoPP::ECB_Mode<CryptoPP::DES>::Encryption des;
        des.SetKey((const CryptoPP::byte*)key.data(), CryptoPP::DES::KEYLENGTH);
        CryptoPP::StringSource(plaintext, true,
            new CryptoPP::StreamTransformationFilter(des,
                new CryptoPP::StringSink(ciphertext)
            )
        );
        return ciphertext;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "DES encryption error: " << e.what() << std::endl;
        throw std::runtime_error("DES encryption failed");
    }
}

// DES 解密
std::string des_decrypt(const std::string& ciphertext, const std::string& key) {
    try {
        std::string plaintext;
        CryptoPP::ECB_Mode<CryptoPP::DES>::Decryption des;
        des.SetKey((const CryptoPP::byte*)key.data(), CryptoPP::DES::KEYLENGTH);
        CryptoPP::StringSource(ciphertext, true,
            new CryptoPP::StreamTransformationFilter(des,
                new CryptoPP::StringSink(plaintext)
            )
        );
        return plaintext;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "DES decryption error: " << e.what() << std::endl;
        throw std::runtime_error("DES decryption failed");
    }
}

// RSA 密钥生成
void rsa_generate_keys(int& p, int& q, int& e, int& d, int& n) {
    p = 101; // 小质数
    q = 103; // 小质数
    n = p * q; // n < 2^16 (10403)
    int phi = (p - 1) * (q - 1);
    e = 7; // gcd(e, phi) = 1
    d = mod_inverse(e, phi);
}

// RSA 加密
std::string rsa_encrypt(const std::string& plaintext, int e, int n) {
    std::string ciphertext;
    for (char c : plaintext) {
        int m = static_cast<unsigned char>(c);
        int c_val = mod_exp(m, e, n);
        ciphertext += (char)(c_val >> 8);
        ciphertext += (char)(c_val & 0xFF);
    }
    return ciphertext;
}

// RSA 解密
std::string rsa_decrypt(const std::string& ciphertext, int d, int n) {
    std::string plaintext;
    for (size_t i = 0; i < ciphertext.size(); i += 2) {
        int c = (static_cast<unsigned char>(ciphertext[i]) << 8) |
                static_cast<unsigned char>(ciphertext[i + 1]);
        int m = mod_exp(c, d, n);
        plaintext += (char)m;
    }
    return plaintext;
}

// SHA-1 哈希
std::string compute_sha1(const std::string& message) {
    try {
        std::string digest;
        CryptoPP::SHA1 sha1;
        CryptoPP::StringSource(message, true,
            new CryptoPP::HashFilter(sha1,
                new CryptoPP::StringSink(digest)
            )
        );
        return digest;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "SHA-1 error: " << e.what() << std::endl;
        throw std::runtime_error("SHA-1 computation failed");
    }
}

std::string rsa_sign(const std::string& hash, int d, int n) {
    int h_trunc = (static_cast<unsigned char>(hash[0]) << 8) |
                  static_cast<unsigned char>(hash[1]);
    int s = mod_exp(h_trunc, d, n);
    std::string signature;
    signature += (char)(s >> 8);
    signature += (char)(s & 0xFF);
    return signature;
}

bool rsa_verify(const std::string& hash, const std::string& signature, int e, int n) {
    int h_trunc = (static_cast<unsigned char>(hash[0]) << 8) |
                  static_cast<unsigned char>(hash[1]);
    int s = (static_cast<unsigned char>(signature[0]) << 8) |
            static_cast<unsigned char>(signature[1]);
    int h_verify = mod_exp(s, e, n);
    return h_verify == h_trunc;
}