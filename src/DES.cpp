#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <tinyxml2.h>
#include <string>
#include <stdexcept>

using namespace CryptoPP;
namespace tx = tinyxml2;

// 从XML配置文件读取DES密钥
std::string ReadDESKeyFromXML(const std::string& configPath) {
    tx::XMLDocument doc;
    if (doc.LoadFile(configPath.c_str()) != tx::XML_SUCCESS) {
        throw std::runtime_error("无法加载XML配置文件");
    }
    
    tx::XMLElement* root = doc.FirstChildElement("Config");
    if (!root) {
        throw std::runtime_error("XML根元素'Config'未找到");
    }
    
    tx::XMLElement* keyElem = root->FirstChildElement("EncryptionKey");
    if (!keyElem || !keyElem->GetText()) {
        throw std::runtime_error("未找到加密密钥元素");
    }
    
    std::string key = keyElem->GetText();
    if (key.size() != 8) {
        throw std::runtime_error("DES密钥必须为8个字符");
    }
    
    return key;
}

// DES加密函数（返回原始字节）
std::string DES_Encrypt(const std::string& plaintext, const std::string& configPath) {
    std::string key = ReadDESKeyFromXML(configPath);
    
    try {
        ECB_Mode<DES>::Encryption encryptor;
        encryptor.SetKey((const byte*)key.data(), DES::DEFAULT_KEYLENGTH);
        
        std::string ciphertext;
        StringSource(plaintext, true,
            new StreamTransformationFilter(encryptor,
                new StringSink(ciphertext),
                BlockPaddingScheme::PKCS_PADDING
            )
        );
        
        return ciphertext;
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("加密错误: " + std::string(e.what()));
    }
}

// DES加密函数（返回Base64编码）
std::string DES_EncryptToBase64(const std::string& plaintext, const std::string& configPath) {
    std::string ciphertext = DES_Encrypt(plaintext, configPath);
    std::string base64Text;
    
    StringSource(ciphertext, true,
        new Base64Encoder(
            new StringSink(base64Text),
            false // 不插入换行符
        )
    );
    
    return base64Text;
}

/* 示例XML配置文件（config.xml）：
<Config>
    <EncryptionKey>my8bykey</EncryptionKey>
</Config>
*/