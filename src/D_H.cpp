#include <iostream>
#include <string>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <crypto++/dh.h>
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/hex.h>
#include <crypto++/sha.h>
#include <crypto++/queue.h>

using namespace CryptoPP;
using namespace std;

// 网络工具函数
int CreateServerSocket(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    
    bind(sock, (sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(sock, 5);
    return sock;
}

int CreateClientSocket(const char* ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &serverAddr.sin_addr);
    
    connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr));
    return sock;
}

string ReadLine(int sock) {
    string data;
    char c;
    while(recv(sock, &c, 1, 0) > 0) {
        if(c == '\n') break;
        data += c;
    }
    return data;
}

void SendLine(int sock, const string& data) {
    send(sock, data.c_str(), data.size(), 0);
    send(sock, "\n", 1, 0);
}

// 密钥序列化工具
string SerializeKey(const RSA::PublicKey& key) {
    string data;
    Base64Encoder encoder(new StringSink(data));
    key.Save(encoder);
    encoder.MessageEnd();
    return data;
}

void DeserializeKey(const string& data, RSA::PublicKey& key) {
    StringSource ss(data, true, new Base64Decoder);
    key.Load(ss);
}

// D-H 参数初始化
void InitializeDH(DH& dh) {
    Integer p("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
              "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
              "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
              "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
              "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
              "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
              "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
              "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
              "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
              "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
              "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
              "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
              "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
              "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
              "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
              "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF");
    Integer g = 2;
    dh.AccessGroupParameters().Initialize(p, g);
}

// 服务器端实现
void RunServer() {
    AutoSeededRandomPool rng;
    
    // 生成RSA密钥对
    RSA::PrivateKey rsaPrivate;
    rsaPrivate.GenerateRandomWithKeySize(rng, 2048);
    RSA::PublicKey rsaPublic(rsaPrivate);
    
    // 启动服务器
    int serverSock = CreateServerSocket(8080);
    cout << "Server waiting for connection..." << endl;
    int clientSock = accept(serverSock, NULL, NULL);
    
    // 交换RSA公钥
    SendLine(clientSock, SerializeKey(rsaPublic));
    RSA::PublicKey clientRsaPublic;
    DeserializeKey(ReadLine(clientSock), clientRsaPublic);
    
    // 交换D-H公钥
    DH dh; InitializeDH(dh);
    SecByteBlock dhPriv(dh.PrivateKeyLength()), dhPub(dh.PublicKeyLength());
    dh.GenerateKeyPair(rng, dhPriv, dhPub);
    
    // 签名并发送D-H公钥
    string dhPubStr((const char*)dhPub.BytePtr(), dhPub.SizeInBytes());
    string signature;
    RSASS<PKCS1v15, SHA1>::Signer signer(rsaPrivate);
    StringSource ss(dhPubStr, true, 
        new SignerFilter(rng, signer,
            new Base64Encoder(new StringSink(signature))));
    
    SendLine(clientSock, Base64Encode(dhPub.BytePtr(), dhPub.SizeInBytes()));
    SendLine(clientSock, signature);
    
    // 接收并验证客户端D-H公钥
    string clientDhPubB64 = ReadLine(clientSock);
    string clientSig = ReadLine(clientSock);
    SecByteBlock clientDhPub;
    Base64Decode(clientDhPubB64, clientDhPub);
    
    bool valid = false;
    RSASS<PKCS1v15, SHA1>::Verifier verifier(clientRsaPublic);
    StringSource ss2(clientSig + string((const char*)clientDhPub.BytePtr(), clientDhPub.SizeInBytes()), true,
        new SignatureVerificationFilter(verifier,
            new ArraySink((byte*)&valid, sizeof(valid)),
            SignatureVerificationFilter::PUT_RESULT | 
            SignatureVerificationFilter::SIGNATURE_AT_END));
    
    if(!valid) {
        cerr << "Client DH public key verification failed!" << endl;
        exit(1);
    }
    
    // 计算共享密钥
    SecByteBlock sharedSecret(dh.AgreedValueLength());
    dh.Agree(sharedSecret, dhPriv, clientDhPub);
    
    cout << "Shared secret established. Length: " << sharedSecret.size() << endl;
    
    // 消息通信
    while(true) {
        string message = ReadLine(clientSock);
        string recvSig = ReadLine(clientSock);
        
        // 验证签名
        string digest;
        SHA1 sha;
        StringSource ss(message, true, new HashFilter(sha, new HexEncoder(new StringSink(digest))));
        
        bool msgValid = false;
        RSASS<PKCS1v15, SHA1>::Verifier msgVerifier(clientRsaPublic);
        StringSource ss3(recvSig + digest, true,
            new SignatureVerificationFilter(msgVerifier,
                new ArraySink((byte*)&msgValid, sizeof(msgValid)),
                SignatureVerificationFilter::PUT_RESULT | 
                SignatureVerificationFilter::SIGNATURE_AT_END));
        
        if(msgValid) {
            cout << "Verified message: " << message << endl;
            SendLine(clientSock, "ACK");
        } else {
            SendLine(clientSock, "INVALID");
        }
    }
}

// 客户端实现
void RunClient() {
    AutoSeededRandomPool rng;
    
    // 生成RSA密钥对
    RSA::PrivateKey rsaPrivate;
    rsaPrivate.GenerateRandomWithKeySize(rng, 2048);
    RSA::PublicKey rsaPublic(rsaPrivate);
    
    // 连接服务器
    int sock = CreateClientSocket("127.0.0.1", 8080);
    
    // 交换RSA公钥
    RSA::PublicKey serverRsaPublic;
    DeserializeKey(ReadLine(sock), serverRsaPublic);
    SendLine(sock, SerializeKey(rsaPublic));
    
    // 交换D-H公钥
    DH dh; InitializeDH(dh);
    SecByteBlock dhPriv(dh.PrivateKeyLength()), dhPub(dh.PublicKeyLength());
    dh.GenerateKeyPair(rng, dhPriv, dhPub);
    
    // 签名并发送D-H公钥
    string dhPubStr((const char*)dhPub.BytePtr(), dhPub.SizeInBytes());
    string signature;
    RSASS<PKCS1v15, SHA1>::Signer signer(rsaPrivate);
    StringSource ss(dhPubStr, true, 
        new SignerFilter(rng, signer,
            new Base64Encoder(new StringSink(signature))));
    
    SendLine(sock, Base64Encode(dhPub.BytePtr(), dhPub.SizeInBytes()));
    SendLine(sock, signature);
    
    // 接收并验证服务器D-H公钥
    string serverDhPubB64 = ReadLine(sock);
    string serverSig = ReadLine(sock);
    SecByteBlock serverDhPub;
    Base64Decode(serverDhPubB64, serverDhPub);
    
    bool valid = false;
    RSASS<PKCS1v15, SHA1>::Verifier verifier(serverRsaPublic);
    StringSource ss2(serverSig + string((const char*)serverDhPub.BytePtr(), serverDhPub.SizeInBytes()), true,
        new SignatureVerificationFilter(verifier,
            new ArraySink((byte*)&valid, sizeof(valid)),
            SignatureVerificationFilter::PUT_RESULT | 
            SignatureVerificationFilter::SIGNATURE_AT_END));
    
    if(!valid) {
        cerr << "Server DH public key verification failed!" << endl;
        exit(1);
    }
    
    // 计算共享密钥
    SecByteBlock sharedSecret(dh.AgreedValueLength());
    dh.Agree(sharedSecret, dhPriv, serverDhPub);
    
    cout << "Shared secret established. Length: " << sharedSecret.size() << endl;
    
    // 发送验证消息
    string message = "Hello from client";
    string digest;
    SHA1 sha;
    StringSource ss3(message, true, new HashFilter(sha, new HexEncoder(new StringSink(digest))));
    
    string msgSig;
    RSASS<PKCS1v15, SHA1>::Signer msgSigner(rsaPrivate);
    StringSource ss4(digest, true, 
        new SignerFilter(rng, msgSigner,
            new Base64Encoder(new StringSink(msgSig))));
    
    SendLine(sock, message);
    SendLine(sock, msgSig);
    
    cout << "Server response: " << ReadLine(sock) << endl;
}

int main(int argc, char* argv[]) {
    if(argc < 2) {
        cerr << "Usage: " << argv[0] << " [server|client]" << endl;
        return 1;
    }
    
    if(string(argv[1]) == "server") RunServer();
    else if(string(argv[1]) == "client") RunClient();
    else cerr << "Invalid argument" << endl;
    
    return 0;
}