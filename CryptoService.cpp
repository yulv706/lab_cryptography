#include <crow.h>
#include <crow/middlewares/cors.h>
#include <tinyxml2.h>
#include <string>
#include <cryptopp/base64.h>
#include "CryptoCore.h"

using namespace tinyxml2;

// 配置结构体
struct Config {
    int affine_a, affine_b;
    std::string rc4_key, des_key;
    unsigned int lfsr_seed;
};

// 从 XML 加载配置
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
    return true;
}

// 辅助函数：添加 CORS 头
void add_cors_headers(crow::response& res) {
    CROW_LOG_DEBUG << "Adding CORS headers to response";
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type, Accept");
}

bool update_affine_config(int a, int b) {
    XMLDocument doc;
    if (doc.LoadFile("config.xml") != XML_SUCCESS) {
        // 创建新配置如果文件不存在
        XMLElement* root = doc.NewElement("config");
        doc.InsertFirstChild(root);

        // 初始化必要字段
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
    
    // 更新 affine_a
    XMLElement* affine_a = root->FirstChildElement("affine_a");
    if (!affine_a) {
        affine_a = doc.NewElement("affine_a");
        root->InsertEndChild(affine_a);
    }
    affine_a->SetText(a);

    // 更新 affine_b
    XMLElement* affine_b = root->FirstChildElement("affine_b");
    if (!affine_b) {
        affine_b = doc.NewElement("affine_b");
        root->InsertEndChild(affine_b);
    }
    affine_b->SetText(b);

    // 保存其他已有字段（如果存在）
    if (XMLElement* rc4_key = root->FirstChildElement("rc4_key")) {
        // 保持现有值不变
    } else {
        // 如果不存在则创建默认
        rc4_key = doc.NewElement("rc4_key");
        rc4_key->SetText("default_rc4");
        root->InsertEndChild(rc4_key);
    }

    // 其他字段类似处理...

    return doc.SaveFile("config.xml") == XML_SUCCESS;
}
// 新增参数验证函数
bool is_valid_a(int a) {
    if (a <= 0 || a >= 26) return false;
    // 检查a是否与26互质
    int gcd = 26;
    int temp = a;
    while (temp != 0) {
        int remainder = gcd % temp;
        gcd = temp;
        temp = remainder;
    }
    return gcd == 1;
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

    // 仿射密码加密
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
            // 更新内存配置
            config.affine_a = a;
            config.affine_b = b;

            // 更新配置文件
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

    // 仿射密码解密
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
            // 更新内存配置
            config.affine_a = a;
            config.affine_b = b;

            // 更新配置文件
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

    // RC4 加密
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

    // RC4 解密
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
            // 解码 Base64 输入
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

    // LFSR + J-K 触发器加密
    CROW_ROUTE(app, "/lfsr_jk/encrypt").methods(crow::HTTPMethod::POST)([&config](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        try {
            CROW_LOG_INFO << "Received /lfsr_jk/encrypt request: " << req.body;
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
            std::string ciphertext = lfsr_jk_encrypt(plaintext, config.lfsr_seed);
            std::string encoded_ciphertext;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_ciphertext));
            encoder.Put((const CryptoPP::byte*)ciphertext.data(), ciphertext.size());
            encoder.MessageEnd();
            res.body = crow::json::wvalue{{"ciphertext", encoded_ciphertext}}.dump();
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /lfsr_jk/encrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            return res;
        }
    });

    // LFSR + J-K 触发器解密
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

    // DES 加密
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

    // DES 解密
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

    // RSA 加密
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

    // RSA 解密
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

    // SHA-1 哈希
    CROW_ROUTE(app, "/sha1").methods(crow::HTTPMethod::POST)([](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        try {
            CROW_LOG_INFO << "Received /sha1 request: " << req.body;
            auto params = crow::json::load(req.body);
            if (!params) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "无效的 JSON 格式"}}.dump();
                return res;
            }
            if (!params.has("message")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少消息参数"}}.dump();
                return res;
            }
            std::string message = params["message"].s();
            if (message.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "消息不能为空"}}.dump();
                return res;
            }
            std::string hash = compute_sha1(message);
            std::string encoded_hash;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_hash));
            encoder.Put((const CryptoPP::byte*)hash.data(), hash.size());
            encoder.MessageEnd();
            res.body = crow::json::wvalue{{"hash", encoded_hash}}.dump();
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /sha1: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            return res;
        }
    });

    // RSA 签名
    CROW_ROUTE(app, "/rsa/sign").methods(crow::HTTPMethod::POST)([d_rsa, n_rsa](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        try {
            CROW_LOG_INFO << "Received /rsa/sign request: " << req.body;
            auto params = crow::json::load(req.body);
            if (!params) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "无效的 JSON 格式"}}.dump();
                return res;
            }
            if (!params.has("message")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少消息参数"}}.dump();
                return res;
            }
            std::string message = params["message"].s();
            if (message.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "消息不能为空"}}.dump();
                return res;
            }
            std::string signature = rsa_sign(message, d_rsa, n_rsa);
            std::string encoded_signature;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_signature));
            encoder.Put((const CryptoPP::byte*)signature.data(), signature.size());
            encoder.MessageEnd();
            res.body = crow::json::wvalue{{"signature", encoded_signature}}.dump();
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /rsa/sign: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            return res;
        }
    });

    // RSA 验证
    CROW_ROUTE(app, "/rsa/verify").methods(crow::HTTPMethod::POST)([e_rsa, n_rsa](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        try {
            CROW_LOG_INFO << "Received /rsa/verify request: " << req.body;
            auto params = crow::json::load(req.body);
            if (!params) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "无效的 JSON 格式"}}.dump();
                return res;
            }
            if (!params.has("message") || !params.has("signature")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少消息或签名参数"}}.dump();
                return res;
            }
            std::string message = params["message"].s();
            std::string encoded_signature = params["signature"].s();
            if (message.empty() || encoded_signature.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "消息或签名不能为空"}}.dump();
                return res;
            }
            std::string signature;
            CryptoPP::Base64Decoder decoder(new CryptoPP::StringSink(signature));
            decoder.Put((const CryptoPP::byte*)encoded_signature.data(), encoded_signature.size());
            decoder.MessageEnd();
            bool valid = rsa_verify(message, signature, e_rsa, n_rsa);
            res.body = crow::json::wvalue{{"valid", valid}}.dump();
            return res;
        } catch (const CryptoPP::Exception& e) {
            CROW_LOG_ERROR << "Error in /rsa/verify: " << e.what();
            res.code = 400;
            res.body = crow::json::wvalue{{"error", "无效的 Base64 签名: " + std::string(e.what())}}.dump();
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /rsa/verify: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            return res;
        }
    });
    
    // D-H 端点
    CROW_ROUTE(app, "/dh").methods(crow::HTTPMethod::POST)([e_rsa, d_rsa, n_rsa](const crow::request& req) {
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
            if (!params.has("message") || !params.has("role")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少消息或角色参数"}}.dump();
                return res;
            }
            std::string message = params["message"].s();
            std::string role = params["role"].s();
            if (message.empty() || role.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "消息或角色不能为空"}}.dump();
                return res;
            }
            if (role != "server" && role != "client") {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "无效的角色参数"}}.dump();
                return res;
            }
    
            int p = 997, g = 2;
            int private_key = (role == "server") ? 123 : 456;
            int public_key = mod_exp(g, private_key, p);
            int other_public_key = mod_exp(g, (role == "server") ? 456 : 123, p);
            int shared_key = mod_exp(other_public_key, private_key, p);
            CROW_LOG_INFO << "Shared Key (int): " << shared_key;
    
            std::string hash = compute_sha1(message);
            CROW_LOG_INFO << "SHA-1 Hash: " << hash;
            std::string signature = rsa_sign(hash, d_rsa, n_rsa);
            CROW_LOG_INFO << "Signature: " << signature;
            std::string encoded_signature;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_signature));
            encoder.Put((const CryptoPP::byte*)signature.data(), signature.size());
            encoder.MessageEnd();
    
            bool valid = rsa_verify(hash, signature, e_rsa, n_rsa);
            CROW_LOG_INFO << "Signature Valid: " << valid;
            std::string encoded_shared_key;
            CryptoPP::Base64Encoder key_encoder(new CryptoPP::StringSink(encoded_shared_key));
            uint32_t shared_key_be = htonl(shared_key); // 转换为大端序
            key_encoder.Put((const CryptoPP::byte*)&shared_key_be, 4);
            key_encoder.MessageEnd();
    
            res.body = crow::json::wvalue{
                {"message", message},
                {"shared_key", encoded_shared_key},
                {"signature", encoded_signature},
                {"signature_valid", valid}
            }.dump();
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