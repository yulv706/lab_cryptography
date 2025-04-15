#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <memory>
#include <cstdint>
#include <stdexcept>

#include <crypto++/arc4.h>
#include <crypto++/hex.h>
#include <pugixml.hpp>

using namespace CryptoPP;

// 密钥生成器基类
class KeyGenerator {
public:
    virtual uint8_t generateByte() = 0;
    virtual ~KeyGenerator() = default;
};

// RC4生成器
class RC4Generator : public KeyGenerator {
private:
    CryptoPP::ARC4 arc4;
public:
    RC4Generator(const byte* key, size_t length) {
        arc4.SetKey(key, length);
    }
    uint8_t generateByte() override {
        byte out;
        arc4.GenerateBlock(&out, 1);
        return out;
    }
};

// LFSR类
class LFSR {
private:
    uint32_t state;
    uint32_t poly;
    int length;

public:
    LFSR(uint32_t initialState, uint32_t polynomial, int bits)
        : state(initialState), poly(polynomial), length(bits) {
        state &= (1 << length) - 1;
    }

    bool next() {
        uint32_t masked = state & poly;
        bool feedback = 0;
        while (masked) {
            feedback ^= (masked & 1);
            masked >>= 1;
        }
        bool output = (state >> (length - 1)) & 1;
        state = ((state << 1) | feedback) & ((1 << length) - 1);
        return output;
    }
};

// J-K触发器类
class JKTrigger {
private:
    bool state;

public:
    JKTrigger(bool initialState) : state(initialState) {}

    bool next(bool j, bool k) {
        bool current = state;
        if (j && k) {
            state = !current;
        } else if (j) {
            state = true;
        } else if (k) {
            state = false;
        }
        return current;
    }
};

// LFSR+J-K生成器
class LFSRJKGenerator : public KeyGenerator {
private:
    LFSR lfsr1;
    LFSR lfsr2;
    JKTrigger trigger;

public:
    LFSRJKGenerator(uint32_t seed1, uint32_t poly1, int bits1,
                    uint32_t seed2, uint32_t poly2, int bits2,
                    bool triggerInitial)
        : lfsr1(seed1, poly1, bits1),
          lfsr2(seed2, poly2, bits2),
          trigger(triggerInitial) {}

    uint8_t generateByte() override {
        uint8_t key = 0;
        for (int i = 0; i < 8; ++i) {
            bool j = lfsr1.next();
            bool k = lfsr2.next();
            bool bit = trigger.next(j, k);
            key |= (bit << (7 - i));
        }
        return key;
    }
};

// 配置结构
struct Rc4Config { std::string keyHex; };
struct LfsrJkConfig {
    uint32_t lfsr1Poly, lfsr1Initial;
    int lfsr1Bits;
    uint32_t lfsr2Poly, lfsr2Initial;
    int lfsr2Bits;
    bool triggerInitial;
};
struct Config {
    std::string algorithm;
    Rc4Config rc4;
    LfsrJkConfig lfsrjk;
};

// 辅助函数
uint32_t parseUint(const std::string& s) {
    std::istringstream iss(s);
    uint32_t value;
    iss >> (s.substr(0, 2) == "0x" ? std::hex : std::dec) >> value;
    if (iss.fail()) throw std::runtime_error("Invalid number: " + s);
    return value;
}

int parseInt(const std::string& s) {
    int value;
    std::istringstream(s) >> value;
    return value;
}

// XML解析
Config parseConfig(const std::string& filename) {
    pugi::xml_document doc;
    if (!doc.load_file(filename.c_str()))
        throw std::runtime_error("XML load failed");

    auto algo = doc.child("StreamCipher").child("Algorithm");
    std::string type = algo.attribute("type").as_string();
    Config config;
    config.algorithm = type;

    if (type == "RC4") {
        config.rc4.keyHex = algo.child("Key").text().as_string();
    } else if (type == "LFSR_JK") {
        auto l1 = algo.child("LFSR1"), l2 = algo.child("LFSR2");
        auto jk = algo.child("JKTrigger");
        config.lfsrjk.lfsr1Poly = parseUint(l1.attribute("polynomial").as_string());
        config.lfsrjk.lfsr1Initial = parseUint(l1.attribute("initial").as_string());
        config.lfsrjk.lfsr1Bits = parseInt(l1.attribute("bits").as_string());
        config.lfsrjk.lfsr2Poly = parseUint(l2.attribute("polynomial").as_string());
        config.lfsrjk.lfsr2Initial = parseUint(l2.attribute("initial").as_string());
        config.lfsrjk.lfsr2Bits = parseInt(l2.attribute("bits").as_string());
        config.lfsrjk.triggerInitial = jk.attribute("initial").as_bool();
    } else {
        throw std::runtime_error("Unsupported algorithm");
    }
    return config;
}

// 创建生成器
std::unique_ptr<KeyGenerator> createGenerator(const Config& config) {
    if (config.algorithm == "RC4") {
        std::string keyBytes;
        StringSource(config.rc4.keyHex, true, new HexDecoder(new StringSink(keyBytes)));
        return std::make_unique<RC4Generator>(
            reinterpret_cast<const byte*>(keyBytes.data()), keyBytes.size());
    } else if (config.algorithm == "LFSR_JK") {
        auto& c = config.lfsrjk;
        return std::make_unique<LFSRJKGenerator>(
            c.lfsr1Initial, c.lfsr1Poly, c.lfsr1Bits,
            c.lfsr2Initial, c.lfsr2Poly, c.lfsr2Bits,
            c.triggerInitial);
    }
    return nullptr;
}

// 文件处理
void processFile(const std::string& inFile, const std::string& outFile, KeyGenerator& gen) {
    std::ifstream in(inFile, std::ios::binary);
    std::ofstream out(outFile, std::ios::binary);
    char buf[4096];
    while (in.read(buf, sizeof(buf)) || in.gcount()) {
        size_t len = in.gcount();
        for (size_t i = 0; i < len; ++i) {
            buf[i] ^= gen.generateByte();
        }
        out.write(buf, len);
    }
}

int main(int argc, char​**​ argv) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <input> <output>\n";
        return 1;
    }

    try {
        Config config = parseConfig("config.xml");
        auto generator = createGenerator(config);
        processFile(argv[1], argv[2], *generator);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}