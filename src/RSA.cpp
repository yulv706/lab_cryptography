#include <iostream>
#include <vector>
#include <random>
#include <algorithm>
#include <numeric>
using namespace std;

// 快速幂取模算法
uint64_t pow_mod(uint64_t base, uint64_t exponent, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exponent > 0) {
        if (exponent & 1) {
            result = (result * base) % mod;
        }
        exponent >>= 1;
        base = (base * base) % mod;
    }
    return result;
}

// 米勒-拉宾素性测试
bool is_prime(uint64_t n, int iterations = 5) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0) return false;

    uint64_t d = n - 1;
    int s = 0;
    while (d % 2 == 0) {
        d /= 2;
        s++;
    }

    const int bases[] = {2, 3, 5, 7, 11};
    for (int a : bases) {
        if (a >= n) continue;
        uint64_t x = pow_mod(a, d, n);
        if (x == 1 || x == n - 1) continue;
        for (int j = 0; j < s - 1; j++) {
            x = pow_mod(x, 2, n);
            if (x == n - 1) break;
        }
        if (x != n - 1) return false;
    }
    return true;
}

// 生成指定范围内的素数
uint64_t generate_prime(uint64_t min, uint64_t max) {
    random_device rd;
    mt19937_64 gen(rd());
    uniform_int_distribution<uint64_t> dist(min, max);

    while (true) {
        uint64_t n = dist(gen);
        if (n % 2 == 0 && n != 2) continue;
        if (is_prime(n)) return n;
    }
}

// 扩展欧几里得算法求模逆元
uint64_t mod_inverse(uint64_t a, uint64_t m) {
    int64_t m0 = m, y = 0, x = 1;
    if (m == 1) return 0;

    while (a > 1) {
        uint64_t q = a / m;
        uint64_t t = m;
        m = a % m, a = t;
        t = y;
        y = x - q * y;
        x = t;
    }

    return x < 0 ? x + m0 : x;
}

// 生成RSA密钥对
void generate_keys(uint64_t &e, uint64_t &d, uint64_t &n) {
    uint64_t p, q;
    do {
        p = generate_prime(2, 255);
        q = generate_prime(2, 255);
        n = p * q;
    } while (n >= 65536 || n < 256);

    uint64_t phi = (p-1) * (q-1);
    
    // 选择公共指数
    e = 65537;
    while (e >= phi || gcd(e, phi) != 1) {
        if (e <= 2) { generate_keys(e, d, n); return; }
        e--;
    }

    d = mod_inverse(e, phi);
}

// RSA加密函数
vector<uint16_t> rsa_encrypt(const string &message, uint64_t e, uint64_t n) {
    vector<uint16_t> ciphertext;
    for (char ch : message) {
        uint64_t m = static_cast<uint8_t>(ch);
        ciphertext.push_back(pow_mod(m, e, n));
    }
    return ciphertext;
}

// RSA解密函数
string rsa_decrypt(const vector<uint16_t> &ciphertext, uint64_t d, uint64_t n) {
    string message;
    for (uint16_t c : ciphertext) {
        message += static_cast<char>(pow_mod(c, d, n));
    }
    return message;
}

int main() {
    uint64_t e, d, n;
    generate_keys(e, d, n);

    cout << "公钥 (" << e << ", " << n << ")\n";
    cout << "私钥 (" << d << ", " << n << ")\n";

    string message = "Hello, RSA!";
    auto ciphertext = rsa_encrypt(message, e, n);
    string decrypted = rsa_decrypt(ciphertext, d, n);

    cout << "\n原始消息: " << message << endl;
    cout << "解密结果: " << decrypted << endl;

    return 0;
}