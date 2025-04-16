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

// 辅助函数：添加 CORS 头（后备）
void add_cors_headers(crow::response& res) {
    CROW_LOG_DEBUG << "Adding CORS headers to response";
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type, Accept");
}

int main() {
    // 使用 CORSHandler 中间件
    crow::App<crow::CORSHandler> app;
    app.loglevel(crow::LogLevel::Debug); // 启用调试日志

    // 配置全局 CORS 规则
    auto& cors = app.get_middleware<crow::CORSHandler>();
    cors.global()
        .origin("*") // 允许所有源，或指定 "http://192.168.3.6:8000"
        .methods("GET"_method, "POST"_method, "OPTIONS"_method)
        .headers("Content-Type", "Accept")
        .max_age(86400); // 预检请求缓存 24 小时

    // 加载配置
    Config config;
    if (!load_config(config)) {
        CROW_LOG_ERROR << "Failed to load config.xml";
        std::cerr << "无法加载 config.xml\n";
        return 1;
    }
    CROW_LOG_INFO << "Config loaded successfully";

    // RSA 密钥（用于加密和签名）
    int p_rsa, q_rsa, e_rsa, d_rsa, n_rsa;
    rsa_generate_keys(p_rsa, q_rsa, e_rsa, d_rsa, n_rsa);

    // D-H 密钥交换参数
    int server_e = 7, server_n = 10403;
    int client_e = 7, client_n = 10403;

    // 主页路由
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
                add_cors_headers(res);
                return res;
            }
            if (!params.has("plaintext")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少明文参数"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string plaintext = params["plaintext"].s();
            if (plaintext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "明文不能为空"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string ciphertext = affine_encrypt(plaintext, config.affine_a, config.affine_b);
            res.body = crow::json::wvalue{{"ciphertext", ciphertext}}.dump();
            add_cors_headers(res);
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /affine/encrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            add_cors_headers(res);
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
                add_cors_headers(res);
                return res;
            }
            if (!params.has("ciphertext")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少密文参数"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string ciphertext = params["ciphertext"].s();
            if (ciphertext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "密文不能为空"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string plaintext = affine_decrypt(ciphertext, config.affine_a, config.affine_b);
            res.body = crow::json::wvalue{{"plaintext", plaintext}}.dump();
            add_cors_headers(res);
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /affine/decrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            add_cors_headers(res);
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
                add_cors_headers(res);
                return res;
            }
            if (!params.has("plaintext")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少明文参数"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string plaintext = params["plaintext"].s();
            if (plaintext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "明文不能为空"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string ciphertext = rc4_encrypt(plaintext, config.rc4_key);
            // 编码为 Base64
            std::string encoded_ciphertext;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_ciphertext));
            encoder.Put((const CryptoPP::byte*)ciphertext.data(), ciphertext.size());
            encoder.MessageEnd();
            res.body = crow::json::wvalue{{"ciphertext", encoded_ciphertext}}.dump();
            add_cors_headers(res);
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /rc4/encrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            add_cors_headers(res);
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
                add_cors_headers(res);
                return res;
            }
            if (!params.has("ciphertext")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少密文参数"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string ciphertext = params["ciphertext"].s();
            if (ciphertext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "密文不能为空"}}.dump();
                add_cors_headers(res);
                return res;
            }
            // 解码 Base64 输入
            std::string decoded_ciphertext;
            CryptoPP::Base64Decoder decoder(new CryptoPP::StringSink(decoded_ciphertext));
            decoder.Put((const CryptoPP::byte*)ciphertext.data(), ciphertext.size());
            decoder.MessageEnd();
            std::string plaintext = rc4_decrypt(decoded_ciphertext, config.rc4_key);
            // 编码为 Base64
            std::string encoded_plaintext;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_plaintext));
            encoder.Put((const CryptoPP::byte*)plaintext.data(), plaintext.size());
            encoder.MessageEnd();
            res.body = crow::json::wvalue{{"plaintext", encoded_plaintext}}.dump();
            add_cors_headers(res);
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /rc4/decrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            add_cors_headers(res);
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
                add_cors_headers(res);
                return res;
            }
            if (!params.has("plaintext")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少明文参数"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string plaintext = params["plaintext"].s();
            if (plaintext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "明文不能为空"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string ciphertext = lfsr_jk_encrypt(plaintext, config.lfsr_seed);
            // 编码为 Base64
            std::string encoded_ciphertext;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_ciphertext));
            encoder.Put((const CryptoPP::byte*)ciphertext.data(), ciphertext.size());
            encoder.MessageEnd();
            res.body = crow::json::wvalue{{"ciphertext", encoded_ciphertext}}.dump();
            add_cors_headers(res);
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /lfsr_jk/encrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            add_cors_headers(res);
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
                add_cors_headers(res);
                return res;
            }
            if (!params.has("ciphertext")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少密文参数"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string ciphertext = params["ciphertext"].s();
            if (ciphertext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "密文不能为空"}}.dump();
                add_cors_headers(res);
                return res;
            }
            // 解码 Base64 输入
            std::string decoded_ciphertext;
            CryptoPP::Base64Decoder decoder(new CryptoPP::StringSink(decoded_ciphertext));
            decoder.Put((const CryptoPP::byte*)ciphertext.data(), ciphertext.size());
            decoder.MessageEnd();
            std::string plaintext = lfsr_jk_decrypt(decoded_ciphertext, config.lfsr_seed);
            // 编码为 Base64
            std::string encoded_plaintext;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_plaintext));
            encoder.Put((const CryptoPP::byte*)plaintext.data(), plaintext.size());
            encoder.MessageEnd();
            res.body = crow::json::wvalue{{"plaintext", encoded_plaintext}}.dump();
            add_cors_headers(res);
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /lfsr_jk/decrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            add_cors_headers(res);
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
                add_cors_headers(res);
                return res;
            }
            if (!params.has("plaintext")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少明文参数"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string plaintext = params["plaintext"].s();
            if (plaintext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "明文不能为空"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string ciphertext = des_encrypt(plaintext, config.des_key);
            // 编码为 Base64
            std::string encoded_ciphertext;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_ciphertext));
            encoder.Put((const CryptoPP::byte*)ciphertext.data(), ciphertext.size());
            encoder.MessageEnd();
            res.body = crow::json::wvalue{{"ciphertext", encoded_ciphertext}}.dump();
            add_cors_headers(res);
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /des/encrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            add_cors_headers(res);
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
                add_cors_headers(res);
                return res;
            }
            if (!params.has("ciphertext")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少密文参数"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string ciphertext = params["ciphertext"].s();
            if (ciphertext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "密文不能为空"}}.dump();
                add_cors_headers(res);
                return res;
            }
            // 解码 Base64 输入
            std::string decoded_ciphertext;
            CryptoPP::Base64Decoder decoder(new CryptoPP::StringSink(decoded_ciphertext));
            decoder.Put((const CryptoPP::byte*)ciphertext.data(), ciphertext.size());
            decoder.MessageEnd();
            std::string plaintext = des_decrypt(decoded_ciphertext, config.des_key);
            // 编码为 Base64
            std::string encoded_plaintext;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_plaintext));
            encoder.Put((const CryptoPP::byte*)plaintext.data(), plaintext.size());
            encoder.MessageEnd();
            res.body = crow::json::wvalue{{"plaintext", encoded_plaintext}}.dump();
            add_cors_headers(res);
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /des/decrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            add_cors_headers(res);
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
                add_cors_headers(res);
                return res;
            }
            if (!params.has("plaintext")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少明文参数"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string plaintext = params["plaintext"].s();
            if (plaintext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "明文不能为空"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string ciphertext = rsa_encrypt(plaintext, e_rsa, n_rsa);
            // 编码为 Base64
            std::string encoded_ciphertext;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_ciphertext));
            encoder.Put((const CryptoPP::byte*)ciphertext.data(), ciphertext.size());
            encoder.MessageEnd();
            res.body = crow::json::wvalue{{"ciphertext", encoded_ciphertext}}.dump();
            add_cors_headers(res);
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /rsa/encrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            add_cors_headers(res);
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
                add_cors_headers(res);
                return res;
            }
            if (!params.has("ciphertext")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少密文参数"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string ciphertext = params["ciphertext"].s();
            if (ciphertext.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "密文不能为空"}}.dump();
                add_cors_headers(res);
                return res;
            }
            // 解码 Base64 输入
            std::string decoded_ciphertext;
            CryptoPP::Base64Decoder decoder(new CryptoPP::StringSink(decoded_ciphertext));
            decoder.Put((const CryptoPP::byte*)ciphertext.data(), ciphertext.size());
            decoder.MessageEnd();
            std::string plaintext = rsa_decrypt(decoded_ciphertext, d_rsa, n_rsa);
            // 编码为 Base64
            std::string encoded_plaintext;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_plaintext));
            encoder.Put((const CryptoPP::byte*)plaintext.data(), plaintext.size());
            encoder.MessageEnd();
            res.body = crow::json::wvalue{{"plaintext", encoded_plaintext}}.dump();
            add_cors_headers(res);
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /rsa/decrypt: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            add_cors_headers(res);
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
                add_cors_headers(res);
                return res;
            }
            if (!params.has("message")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少消息参数"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string message = params["message"].s();
            if (message.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "消息不能为空"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string hash = compute_sha1(message);
            // 编码为 Base64
            std::string encoded_hash;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_hash));
            encoder.Put((const CryptoPP::byte*)hash.data(), hash.size());
            encoder.MessageEnd();
            res.body = crow::json::wvalue{{"hash", encoded_hash}}.dump();
            add_cors_headers(res);
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /sha1: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            add_cors_headers(res);
            return res;
        }
    });

    // RSA 数字签名
    CROW_ROUTE(app, "/rsa/sign").methods(crow::HTTPMethod::POST)([d_rsa, n_rsa](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        try {
            CROW_LOG_INFO << "Received /rsa/sign request: " << req.body;
            auto params = crow::json::load(req.body);
            if (!params) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "无效的 JSON 格式"}}.dump();
                add_cors_headers(res);
                return res;
            }
            if (!params.has("message")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少消息参数"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string message = params["message"].s();
            if (message.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "消息不能为空"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string hash = compute_sha1(message);
            std::string signature = rsa_sign(hash, d_rsa, n_rsa);
            // 编码为 Base64
            std::string encoded_signature;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_signature));
            encoder.Put((const CryptoPP::byte*)signature.data(), signature.size());
            encoder.MessageEnd();
            res.body = crow::json::wvalue{{"signature", encoded_signature}}.dump();
            add_cors_headers(res);
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /rsa/sign: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            add_cors_headers(res);
            return res;
        }
    });

    // RSA 签名验证
    CROW_ROUTE(app, "/rsa/verify").methods(crow::HTTPMethod::POST)([e_rsa, n_rsa](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        try {
            CROW_LOG_INFO << "Received /rsa/verify request: " << req.body;
            auto params = crow::json::load(req.body);
            if (!params) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "无效的 JSON 格式"}}.dump();
                add_cors_headers(res);
                return res;
            }
            if (!params.has("message") || !params.has("signature")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少消息或签名参数"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string message = params["message"].s();
            std::string signature = params["signature"].s();
            if (message.empty() || signature.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "消息或签名不能为空"}}.dump();
                add_cors_headers(res);
                return res;
            }
            // 解码 Base64 签名
            std::string decoded_signature;
            CryptoPP::Base64Decoder decoder(new CryptoPP::StringSink(decoded_signature));
            decoder.Put((const CryptoPP::byte*)signature.data(), signature.size());
            decoder.MessageEnd();
            std::string hash = compute_sha1(message);
            bool valid = rsa_verify(hash, decoded_signature, e_rsa, n_rsa);
            res.body = crow::json::wvalue{{"valid", valid}}.dump();
            add_cors_headers(res);
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /rsa/verify: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            add_cors_headers(res);
            return res;
        }
    });

    // D-H 密钥交换
    CROW_ROUTE(app, "/dh").methods(crow::HTTPMethod::POST)([server_e, server_n, client_e, client_n](const crow::request& req) {
        crow::response res;
        add_cors_headers(res);
        try {
            CROW_LOG_INFO << "Received /dh request: " << req.body;
            auto params = crow::json::load(req.body);
            if (!params) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "无效的 JSON 格式"}}.dump();
                add_cors_headers(res);
                return res;
            }
            if (!params.has("role") || !params.has("message")) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "缺少角色或消息参数"}}.dump();
                add_cors_headers(res);
                return res;
            }
            std::string role = params["role"].s();
            std::string message = params["message"].s();
            if (role.empty() || message.empty()) {
                res.code = 400;
                res.body = crow::json::wvalue{{"error", "角色或消息不能为空"}}.dump();
                add_cors_headers(res);
                return res;
            }
            int p = 997, g = 2;
            int private_key = (role == "server") ? 123 : 456;
            int public_key = mod_exp(g, private_key, p);
            int other_public = (role == "server") ? mod_exp(g, 456, p) : mod_exp(g, 123, p);
            int shared_key = mod_exp(other_public, private_key, p);
            std::string hash = compute_sha1(message);
            int p_client, q_client, e_client, d_client, n_client;
            rsa_generate_keys(p_client, q_client, e_client, d_client, n_client);
            std::string signature = rsa_sign(hash, d_client, n_client);
            // 编码为 Base64
            std::string encoded_signature;
            CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_signature));
            encoder.Put((const CryptoPP::byte*)signature.data(), signature.size());
            encoder.MessageEnd();
            bool verified = rsa_verify(hash, signature, e_client, n_client);
            res.body = crow::json::wvalue{
                {"shared_key", shared_key},
                {"message", message},
                {"signature", encoded_signature},
                {"verified", verified}
            }.dump();
            add_cors_headers(res);
            return res;
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /dh: " << e.what();
            res.code = 500;
            res.body = crow::json::wvalue{{"error", "服务器内部错误: " + std::string(e.what())}}.dump();
            add_cors_headers(res);
            return res;
        }
    });

    // 启动服务器
    CROW_LOG_INFO << "Starting server on 0.0.0.0:8080";
    app.bindaddr("0.0.0.0").port(8080).multithreaded().run();
    return 0;
}