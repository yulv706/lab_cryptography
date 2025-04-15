#include <iostream>
#include <string>
#include <stdexcept>
#include <limits>  // 用于处理无效输入
using namespace std;

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

string affineEncrypt(const string& plaintext, int a, int b) {
    string ciphertext = "";
    for (char c : plaintext) {
        if (isupper(c)) {
            int x = c - 'A';
            int y = (a * x + b) % 26;
            if (y < 0) y += 26;
            ciphertext += (char)(y + 'A');
        } else if (islower(c)) {
            int x = c - 'a';
            int y = (a * x + b) % 26;
            if (y < 0) y += 26;
            ciphertext += (char)(y + 'a');
        } else {
            ciphertext += c;
        }
    }
    return ciphertext;
}

string affineDecrypt(const string& ciphertext, int a, int b) {
    int aInv = modInverse(a, 26);
    string plaintext = "";
    for (char c : ciphertext) {
        if (isupper(c)) {
            int y = c - 'A';
            int x = (aInv * (y - b)) % 26;
            if (x < 0) x += 26;
            plaintext += (char)(x + 'A');
        } else if (islower(c)) {
            int y = c - 'a';
            int x = (aInv * (y - b)) % 26;
            if (x < 0) x += 26;
            plaintext += (char)(x + 'a');
        } else {
            plaintext += c;
        }
    }
    return plaintext;
}

int main() {
    try {
        int a, b;
        string text;

        // 输入密钥a并进行有效性验证
        cout << "请输入密钥a（必须与26互质）: ";
        while (true) {
            if (!(cin >> a)) {
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                cout << "输入无效，请输入整数: ";
                continue;
            }
            if (gcd(a, 26) == 1) break;
            cout << "无效的a值，必须与26互质，请重新输入: ";
        }

        // 输入密钥b
        cout << "请输入密钥b: ";
        while (!(cin >> b)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "输入无效，请输入整数: ";
        }

        // 输入明文
        cout << "请输入明文: ";
        cin.ignore();  // 清除之前的换行符
        getline(cin, text);

        // 加密
        string encrypted = affineEncrypt(text, a, b);
        cout << "\n加密结果: " << encrypted << endl;

        // 解密
        string decrypted = affineDecrypt(encrypted, a, b);
        cout << "解密结果: " << decrypted << endl;

    } catch (const invalid_argument& e) {
        cerr << "错误: " << e.what() << endl;
        return 1;
    }
    return 0;
}