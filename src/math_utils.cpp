#include "math_utils.h"

int gcd(int a, int b) {
    a = abs(a);
    b = abs(b);
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

int modInverse(int a, int m) {
    a = a % m;
    if (a < 0) a += m;  // 确保a为正数
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1)
            return x;
    }
    throw invalid_argument("模逆元不存在");
}