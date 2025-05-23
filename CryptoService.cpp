#include <crow.h>
#include <crow/middlewares/cors.h>
#include <tinyxml2.h>
#include <string>
#include <cryptopp/base64.h>
#include "CryptoCore.h"
#include <cryptopp/hex.h>

using namespace tinyxml2;

// 配置结构体，用于存储加密算法的参数
struct Config {
    int affine_a, affine_b;
    std::string rc4_key, des_key;
    unsigned int lfsr_seed;
};

// 从 config.xml 文件加载配置
bool load_config(Config& config) {
    XMLDocument doc;
    if (doc.LoadFile("config.xml") != XML_SUCCESS) {
        return false;
    }
    XMLElement* root = doc.RootElement();
    config.affine_a = atoi(root->FirstChildElement("affine_a")->GetText());
    config.affine_b = atoi(root->FirstChildElement("affine_b")->GetText());
    config.rc4_key = root->FirstChildElement("rc4_key")->GetText();
    config.des_key = root->FirstChildElement("des_key")->GetText();
    config.lfsr_seed = atoi(root->FirstChildElement("lfsr_seed")->GetText());
     if (XMLElement* rc4_key = root->FirstChildElement("rc4_key")) {
        config.rc4_key = rc4_key->GetText();
    } else {
        config.rc4_key = "default_rc4";  // 默认 RC4 密钥
    }

    if (XMLElement* des_key = root->FirstChildElement("des_key")) {
        config.des_key = des_key->GetText();
    } else {
        config.des_key = "default_des";  // 默认 DES 密钥
    }

    if (XMLElement* lfsr_seed = root->FirstChildElement("lfsr_seed")) {
        config.lfsr_seed = atoi(lfsr_seed->GetText());
    } else {
        config.lfsr_seed = 12345;  // 默认种子
    }
    return true;
}

// 为 HTTP 响应添加 CORS 头
void add_cors_headers(crow::response& res) {
    CROW_LOG_DEBUG << "Adding CORS headers to response";
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type, Accept");
}

// 更新仿射加密的配置参数并保存到 config.xml
bool update_affine_config(int a, int b) {
    XMLDocument doc;
    if (doc.LoadFile("config.xml") != XML_SUCCESS) {
        XMLElement* root = doc.NewElement("config");
        doc.InsertFirstChild(root);

        XMLElement* elem = doc.NewElement("rc4_key");
        elem->SetText("default_rc4");
        root->InsertEndChild(elem);

        elem = doc.NewElement("des_key");
        elem->SetText("default_des");
        root->InsertEndChild(elem);

        elem = doc.NewElement("lfsr_seed");
        elem->SetText(12345);
        root->InsertEndChild(elem);
    }

    XMLElement* root = doc.RootElement();
    
    // 更新 affine_a 参数
    XMLElement* affine_a = root->FirstChildElement("affine_a");
    if (!affine_a) {
        affine_a = doc.NewElement("affine_a");
        root->InsertEndChild(affine_a);
    }
    affine_a->SetText(a);

    // 更新 affine_b 参数
    XMLElement* affine_b = root->FirstChildElement("affine_b");
    if (!affine_b) {
        affine_b = doc.NewElement("affine_b");
        root->InsertEndChild(affine_b);
    }
    affine_b->SetText(b);

    if (XMLElement* rc4_key = root->FirstChildElement("rc4_key")) {
    } else {
        rc4_key = doc.NewElement("rc4_key");
        rc4_key->SetText("default_rc4");
        root->InsertEndChild(rc4_key);
    }

    return doc.SaveFile("config.xml") == XML_SUCCESS;
}

// 验证参数 a 是否与 26 互质
bool is_valid_a(int a) {
    if (a <= 0 || a >= 26) return false;
    int gcd = 26;
    int temp = a;
    while (temp != 0) {
        int remainder = gcd % temp;
        gcd = temp;
        temp = remainder;
    }
    return gcd == 1;
}
// 新增配置更新函数
bool update_rc4_config(const std::string& key) {
    XMLDocument doc;
    if (doc.LoadFile("config.xml") != XML_SUCCESS) {
        XMLElement* root = doc.NewElement("config");
        doc.InsertFirstChild(root);
    }
    
    XMLElement* root = doc.RootElement();
    XMLElement* rc4_key = root->FirstChildElement("rc4_key");
    if (!rc4_key) {
        rc4_key = doc.NewElement("rc4_key");
        root->InsertEndChild(rc4_key);
    }
    rc4_key->SetText(key.c_str());
    return doc.SaveFile("config.xml") == XML_SUCCESS;
}
bool update_des_config(const std::string& key) {
    XMLDocument doc;
    if (doc.LoadFile("config.xml") != XML_SUCCESS) {
        XMLElement* root = doc.NewElement("config");
        doc.InsertFirstChild(root);
    }
    
    XMLElement* root = doc.RootElement();
    XMLElement* des_key = root->FirstChildElement("des_key");
    if (!des_key) {
        des_key = doc.NewElement("des_key");
        root->InsertEndChild(des_key);
    }
    des_key->SetText(key.c_str());
    return doc.SaveFile("config.xml") == XML_SUCCESS;
}
bool update_lfsr_config(const std::string& seed_str) {
    XMLDocument doc;
    if (doc.LoadFile("config.xml") != XML_SUCCESS) {
        XMLElement* root = doc.NewElement("config");
        doc.InsertFirstChild(root);
    }
    
    XMLElement* root = doc.RootElement();
    XMLElement* lfsr_seed = root->FirstChildElement("lfsr_seed");
    if (!lfsr_seed) {
        lfsr_seed = doc.NewElement("lfsr_seed");
        root->InsertEndChild(lfsr_seed);
    }
    lfsr_seed->SetText(seed_str.c_str());
    return doc.SaveFile("config.xml") == XML_SUCCESS;
}


int main() {
    crow::App<crow::CORSHandler> app;
    app.loglevel(crow::LogLevel::Debug);

    auto& cors = app.get_middleware<crow::CORSHandler>();
    cors.global()
        .origin("*")
        .methods("GET"_method, "POST"_method, "OPTIONS"_method)
        .headers("Content-Type", "Accept")
        .max_age(86400);

    Config config;
    if (!load_config(config)) {
        CROW_LOG_ERROR << "Failed to load config.xml";
        std::cerr << "无法加载 config.xml\n";
        return 1;
    }
    CROW_LOG_INFO << "Config loaded successfully";

    int p_rsa, q_rsa, e_rsa, d_rsa, n_rsa;
    rsa_generate_keys(p_rsa, q_rsa, e_rsa, d_rsa, n_rsa);

    CROW_ROUTE(app, "/").methods(crow::HTTPMethod::GET)([](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        res.body = "密码学服务系统 API 已启动";
        return res;
    });

    CROW_ROUTE(app, "/affine/encrypt").methods(crow::HTTPMethod::POST)([&config](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        try {
            CROW_LOG_INFO << "Received /affine/encrypt request: " << req.body;
            auto params = crow::json::load(req.body);
            if (!params) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "无效的 JSON 格式"}}.dump();
                return res;
            }
            if (!params.has("plaintext") || !params.has("a") || !params.has("b")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少必要参数"}}.dump();
                return res;
            }
            std::string plaintext = params["plaintext"].s();
            int a = params["a"].i();
            int b = params["b"].i();
            if (a <= 0 || a >= 26 || !is_valid_a(a)) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "参数a必须与26互质且 1 <= a < 26"}}.dump();
                return res;
            }
            if (b < 0 || b >= 26) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "参数b必须在 0 <= b < 26 范围内"}}.dump();
                return res;
            }
            config.affine_a = a;
            config.affine_b = b;

            if (!update_affine_config(a, b)) {
                CROW_LOG_WARNING << "Failed to update config.xml";
            }
            if (plaintext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "明文不能为空"}}.dump();
                return res;
            }
            std::string ciphertext = affine_encrypt(plaintext, config.affine_a, config.affine_b);
            res.body = crow::json::wvalue{
                {"ciphertext", ciphertext},
                {"current_a", a},
                {"current_b", b}
            }.dump();
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /affine/encrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            return res;
        }
    });

    CROW_ROUTE(app, "/affine/decrypt").methods(crow::HTTPMethod::POST)([&config](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        try {
            CROW_LOG_INFO << "Received /affine/decrypt request: " << req.body;
            auto params = crow::json::load(req.body);
            if (!params) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "无效的 JSON 格式"}}.dump();
                return res;
            }
            if (!params.has("ciphertext") || !params.has("a") || !params.has("b")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少密文参数"}}.dump();
                return res;
            }
            std::string ciphertext = params["ciphertext"].s();
            if (ciphertext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "密文不能为空"}}.dump();
                return res;
            }
            std::string plaintext = affine_decrypt(ciphertext, config.affine_a, config.affine_b);
            int a = params["a"].i();
            int b = params["b"].i();
            if (a <= 0 || a >= 26 || !is_valid_a(a)) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "参数a必须与26互质且 1 <= a < 26"}}.dump();
                return res;
            }
            if (b < 0 || b >= 26) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "参数b必须在 0 <= b < 26 范围内"}}.dump();
                return res;
            }
            config.affine_a = a;
            config.affine_b = b;

            if (!update_affine_config(a, b)) {
                CROW_LOG_WARNING << "Failed to update config.xml";
            }

            res.body = crow::json::wvalue{
                {"plaintext", plaintext},
                {"current_a", a},
                {"current_b", b}
            }.dump();
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /affine/decrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            return res;
        }
    });

    CROW_ROUTE(app, "/rc4/encrypt").methods(crow::HTTPMethod::POST)([&config](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        try {
            CROW_LOG_INFO << "Received /rc4/encrypt request: " << req.body;
            auto params = crow::json::load(req.body);
            if (!params) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "无效的 JSON 格式"}}.dump();
                return res;
            }
            if (!params.has("plaintext")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少明文参数"}}.dump();
                return res;
            }
            std::string plaintext = params["plaintext"].s();
            if (plaintext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "明文不能为空"}}.dump();
                return res;
            }
            if (!params.has("key")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少密钥参数"}}.dump();
                return res;
            }
            std::string key = params["key"].s();
            if (key.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "密钥不能为空"}}.dump();
                return res;
            }
            config.rc4_key = key;
            if (!update_rc4_config(key)) {
                CROW_LOG_WARNING << "RC4 密钥更新失败";
            }
            std::string ciphertext = rc4_encrypt(plaintext, config.rc4_key);
            std::string encoded_ciphertext;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_ciphertext));
            encoder.Put((const CryptoPP::byte*)ciphertext.data(), ciphertext.size());
            encoder.MessageEnd();
            res.body = crow::json::wvalue{{"ciphertext", encoded_ciphertext}}.dump();
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /rc4/encrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            return res;
        }
    });

    CROW_ROUTE(app, "/rc4/decrypt").methods(crow::HTTPMethod::POST)([&config](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        try {
            CROW_LOG_INFO << "Received /rc4/decrypt request: " << req.body;
            auto params = crow::json::load(req.body);
            if (!params) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "无效的 JSON 格式"}}.dump();
                return res;
            }
            if (!params.has("ciphertext")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少密文参数"}}.dump();
                return res;
            }
            std::string encoded_ciphertext = params["ciphertext"].s();
            if (encoded_ciphertext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "密文不能为空"}}.dump();
                return res;
            }
            std::string ciphertext;
            CryptoPP::Base64Decoder decoder(new CryptoPP::StringSink(ciphertext));
            decoder.Put((const CryptoPP::byte*)encoded_ciphertext.data(), encoded_ciphertext.size());
            decoder.MessageEnd();
            std::string plaintext = rc4_decrypt(ciphertext, config.rc4_key);
            res.body = crow::json::wvalue{{"plaintext", plaintext}}.dump();
            return res;
        } catch (const CryptoPP::Exception& e) {
            CROW_LOG_ERROR << "Error in /rc4/decrypt: " << e.what();
            res.code = 400;
            res.body = crow::json::wvalue{{"error", "无效的 Base64 密文: " + std::string(e.what())}}.dump();
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /rc4/decrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            return res;
        }
    });

CROW_ROUTE(app, "/lfsr_jk/encrypt").methods(crow::HTTPMethod::POST)([&config](const crow::request& req) {
    crow::response res;
    add_cors_headers(res);
    
    try {
        CROW_LOG_INFO << "[LFSR] 收到加密请求，请求体大小: " << req.body.size() << " 字节";
        const auto& params = crow::json::load(req.body);

        // 参数基础验证
        if (!params) {
            CROW_LOG_WARNING << "[LFSR] 无效的 JSON 格式";
            res.code = 400;
            res.body = crow::json::wvalue{{"error", "无效的 JSON 格式"}}.dump();
            return res;
        }

        // 必需参数检查
        std::vector<std::string> required_params = {"plaintext", "key"};
        for (const auto& param : required_params) {
            if (!params.has(param)) {
                CROW_LOG_WARNING << "[LFSR] 缺少必要参数: " << param;
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少参数: " + param}}.dump();
                return res;
            }
        }

        // 获取并验证明文
        const std::string plaintext = params["plaintext"].s();
        if (plaintext.empty()) {
            CROW_LOG_WARNING << "[LFSR] 明文内容为空";
            res.code = 400;
            res.body = crow::json::wvalue{{"error", "明文不能为空"}}.dump();
            return res;
        }

        // 获取并验证种子
        const std::string seed_str = params["key"].s();
        if (seed_str.empty()) {
            CROW_LOG_WARNING << "[LFSR] 种子参数为空";
            res.code = 400;
            res.body = crow::json::wvalue{{"error", "种子不能为空"}}.dump();
            return res;
        }

        // 种子格式转换
        unsigned seed = 0;
        try {
            seed = std::stoul(seed_str);
            if (seed > UINT_MAX) {
                throw std::out_of_range("种子值超出范围");
            }
        } catch (const std::invalid_argument&) {
            CROW_LOG_WARNING << "[LFSR] 无效的种子格式: " << seed_str;
            res.code = 400;
            res.body = crow::json::wvalue{{"error", "无效的种子格式，需为无符号整数"}}.dump();
            return res;
        } catch (const std::out_of_range&) {
            CROW_LOG_WARNING << "[LFSR] 种子值超出范围: " << seed_str;
            res.code = 400;
            res.body = crow::json::wvalue{{"error", "种子值超出允许范围 (0-" + std::to_string(UINT_MAX) + ")"}}.dump();
            return res;
        }

        // 更新配置
        CROW_LOG_DEBUG << "[LFSR] 更新 LFSR 种子: " << seed;
        config.lfsr_seed = seed;
        if (!update_lfsr_config(std::to_string(seed))) {
            CROW_LOG_ERROR << "[LFSR] 配置文件更新失败，种子: " << seed;
        }

        // 执行加密
        CROW_LOG_DEBUG << "[LFSR] 开始加密，明文长度: " << plaintext.length();
        const std::string ciphertext = lfsr_jk_encrypt(plaintext, seed);
        
        // Base64 编码
        std::string encoded_ciphertext;
        CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_ciphertext));
        encoder.Put(reinterpret_cast<const CryptoPP::byte*>(ciphertext.data()), ciphertext.size());
        encoder.MessageEnd();

        CROW_LOG_INFO << "[LFSR] 加密成功，密文长度: " << encoded_ciphertext.length();
        res.body = crow::json::wvalue{{"ciphertext", encoded_ciphertext}}.dump();
        return res;

    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "[LFSR] 系统异常: " << typeid(e).name() << " - " << e.what();
        res.code = 500;
        res.body = crow::json::wvalue{
            {"error", "服务器内部错误"},
            {"details", e.what()}
        }.dump();
        return res;
    }
});

    CROW_ROUTE(app, "/lfsr_jk/decrypt").methods(crow::HTTPMethod::POST)([&config](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        try {
            CROW_LOG_INFO << "Received /lfsr_jk/decrypt request: " << req.body;
            auto params = crow::json::load(req.body);
            if (!params) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "无效的 JSON 格式"}}.dump();
                return res;
            }
            if (!params.has("ciphertext")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少密文参数"}}.dump();
                return res;
            }
            std::string encoded_ciphertext = params["ciphertext"].s();
            if (encoded_ciphertext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "密文不能为空"}}.dump();
                return res;
            }
            std::string ciphertext;
            CryptoPP::Base64Decoder decoder(new CryptoPP::StringSink(ciphertext));
            decoder.Put((const CryptoPP::byte*)encoded_ciphertext.data(), encoded_ciphertext.size());
            decoder.MessageEnd();
            std::string plaintext = lfsr_jk_decrypt(ciphertext, config.lfsr_seed);
            res.body = crow::json::wvalue{{"plaintext", plaintext}}.dump();
            return res;
        } catch (const CryptoPP::Exception& e) {
            CROW_LOG_ERROR << "Error in /lfsr_jk/decrypt: " << e.what();
            res.code = 400;
            res.body = crow::json::wvalue{{"error", "无效的 Base64 密文: " + std::string(e.what())}}.dump();
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /lfsr_jk/decrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            return res;
        }
    });

    CROW_ROUTE(app, "/des/encrypt").methods(crow::HTTPMethod::POST)([&config](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        try {
            CROW_LOG_INFO << "Received /des/encrypt request: " << req.body;
            auto params = crow::json::load(req.body);
            if (!params) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "无效的 JSON 格式"}}.dump();
                return res;
            }
            if (!params.has("plaintext")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少明文参数"}}.dump();
                return res;
            }
            std::string plaintext = params["plaintext"].s();
            if (plaintext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "明文不能为空"}}.dump();
                return res;
            }
            if (!params.has("key")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少密钥参数"}}.dump();
                return res;
            }
            std::string key = params["key"].s();
            if (key.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "DES 密钥不能为空"}}.dump();
                return res;
            }
            config.des_key = key;
            if (!update_des_config(key)) {
                CROW_LOG_WARNING << "DES 密钥更新失败";
            }
            std::string ciphertext = des_encrypt(plaintext, config.des_key);
            std::string encoded_ciphertext;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_ciphertext));
            encoder.Put((const CryptoPP::byte*)ciphertext.data(), ciphertext.size());
            encoder.MessageEnd();
            res.body = crow::json::wvalue{{"ciphertext", encoded_ciphertext}}.dump();
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /des/encrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            return res;
        }
    });

    CROW_ROUTE(app, "/des/decrypt").methods(crow::HTTPMethod::POST)([&config](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        try {
            CROW_LOG_INFO << "Received /des/decrypt request: " << req.body;
            auto params = crow::json::load(req.body);
            if (!params) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "无效的 JSON 格式"}}.dump();
                return res;
            }
            if (!params.has("ciphertext")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少密文参数"}}.dump();
                return res;
            }
            std::string encoded_ciphertext = params["ciphertext"].s();
            if (encoded_ciphertext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "密文不能为空"}}.dump();
                return res;
            }
            std::string ciphertext;
            CryptoPP::Base64Decoder decoder(new CryptoPP::StringSink(ciphertext));
            decoder.Put((const CryptoPP::byte*)encoded_ciphertext.data(), encoded_ciphertext.size());
            decoder.MessageEnd();
            std::string plaintext = des_decrypt(ciphertext, config.des_key);
            res.body = crow::json::wvalue{{"plaintext", plaintext}}.dump();
            return res;
        } catch (const CryptoPP::Exception& e) {
            CROW_LOG_ERROR << "Error in /des/decrypt: " << e.what();
            res.code = 400;
            res.body = crow::json::wvalue{{"error", "无效的 Base64 密文: " + std::string(e.what())}}.dump();
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /des/decrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            return res;
        }
    });

    CROW_ROUTE(app, "/rsa/encrypt").methods(crow::HTTPMethod::POST)([e_rsa, n_rsa](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        try {
            CROW_LOG_INFO << "Received /rsa/encrypt request: " << req.body;
            auto params = crow::json::load(req.body);
            if (!params) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "无效的 JSON 格式"}}.dump();
                return res;
            }
            if (!params.has("plaintext")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少明文参数"}}.dump();
                return res;
            }
            std::string plaintext = params["plaintext"].s();
            if (plaintext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "明文不能为空"}}.dump();
                return res;
            }
            std::string ciphertext = rsa_encrypt(plaintext, e_rsa, n_rsa);
            std::string encoded_ciphertext;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_ciphertext));
            encoder.Put((const CryptoPP::byte*)ciphertext.data(), ciphertext.size());
            encoder.MessageEnd();
            res.body = crow::json::wvalue{{"ciphertext", encoded_ciphertext}}.dump();
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /rsa/encrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            return res;
        }
    });

    CROW_ROUTE(app, "/rsa/decrypt").methods(crow::HTTPMethod::POST)([d_rsa, n_rsa](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        try {
            CROW_LOG_INFO << "Received /rsa/decrypt request: " << req.body;
            auto params = crow::json::load(req.body);
            if (!params) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "无效的 JSON 格式"}}.dump();
                return res;
            }
            if (!params.has("ciphertext")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少密文参数"}}.dump();
                return res;
            }
            std::string encoded_ciphertext = params["ciphertext"].s();
            if (encoded_ciphertext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "密文不能为空"}}.dump();
                return res;
            }
            std::string ciphertext;
            CryptoPP::Base64Decoder decoder(new CryptoPP::StringSink(ciphertext));
            decoder.Put((const CryptoPP::byte*)encoded_ciphertext.data(), encoded_ciphertext.size());
            decoder.MessageEnd();
            std::string plaintext = rsa_decrypt(ciphertext, d_rsa, n_rsa);
            res.body = crow::json::wvalue{{"plaintext", plaintext}}.dump();
            return res;
        } catch (const CryptoPP::Exception& e) {
            CROW_LOG_ERROR << "Error in /rsa/decrypt: " << e.what();
            res.code = 400;
            res.body = crow::json::wvalue{{"error", "无效的 Base64 密文: " + std::string(e.what())}}.dump();
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /rsa/decrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            return res;
        }
    });

    
    CROW_ROUTE(app, "/dh").methods(crow::HTTPMethod::POST)([e_rsa, n_rsa](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        try {
            CROW_LOG_INFO << "Received /dh request: " << req.body;
            auto params = crow::json::load(req.body);
            if (!params) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "无效的 JSON 格式"}}.dump();
                return res;
            }
            if (!params.has("encrypted_public_key") || !params.has("signature")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少必要参数"}}.dump();
                return res;
            }
            std::string encrypted_public_key = params["encrypted_public_key"].s();
            std::string signature = params["signature"].s();
            
            std::string decoded_encrypted_public_key;
            CryptoPP::Base64Decoder decoder1(new CryptoPP::StringSink(decoded_encrypted_public_key));
            decoder1.Put((const CryptoPP::byte*)encrypted_public_key.data(), encrypted_public_key.size());
            decoder1.MessageEnd();
            
            std::string decoded_signature;
            CryptoPP::Base64Decoder decoder2(new CryptoPP::StringSink(decoded_signature));
            decoder2.Put((const CryptoPP::byte*)signature.data(), signature.size());
            decoder2.MessageEnd();
            
            std::string decrypted_public_key;

            decrypted_public_key = rsa_decrypt_with_public(decoded_encrypted_public_key, e_rsa, n_rsa);
            
            std::string decrypted_signature = rsa_decrypt_with_public(decoded_signature, e_rsa, n_rsa);
            std::string computed_hash = compute_md5(decrypted_public_key);

            std::string hex_hash;
            CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hex_hash));
            encoder.Put((const CryptoPP::byte*)computed_hash.data(), computed_hash.size());
            encoder.MessageEnd();
            CROW_LOG_INFO << "decrypted_public_key: " << decrypted_public_key;
            CROW_LOG_INFO << "computed_hash hex: " << hex_hash;

            if (computed_hash != decrypted_signature) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "身份验证失败"}}.dump();
                return res;
            }
            
            int p = 997, g = 2;
            int server_private_key = 123;
            int server_public_key = mod_exp(g, server_private_key, p);
            int client_public_key = std::stoi(decrypted_public_key);
            int shared_key = mod_exp(client_public_key, server_private_key, p);
            
            res.body = crow::json::wvalue{{"shared_key", shared_key}}.dump();
            return res;
        } catch (const CryptoPP::Exception& e) {
            CROW_LOG_ERROR << "Error in /dh: " << e.what();
            res.code = 400;
            res.body = crow::json::wvalue{{"error", "无效的 Base64 数据: " + std::string(e.what())}}.dump();
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /dh: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            return res;
        }
    });

    app.port(8080).multithreaded().run();
    return 0;
}