# CryptoService

CryptoService 是一个前后端分离的密码学服务系统，提供基于 Web 的界面，支持多种加密、解密、哈希和密钥交换算法，包括仿射密码、RC4、LFSR + J-K 触发器、DES、RSA和 Diffie-Hellman 密钥交换。后端使用 C++ 和 Crow 框架开发，前端使用 HTML、CSS 和 JavaScript，并基于 Bootstrap 构建。

## 项目结构

项目目录结构如下：

```
crypto
├── build
│   ├── CMakeCache.txt
│   ├── CMakeFiles
│   ├── cmake_install.cmake
│   ├── config.xml
│   ├── CryptoService
│   ├── libCryptoCore.so
│   └── Makefile
├── CMakeLists.txt
├── config.xml
├── CryptoCore.cpp
├── CryptoCore.h
├── CryptoService.cpp
└── web
    ├── index.html
    ├── script.js
    └── style.css
```

## 前置条件

在构建和运行 CryptoService 之前，需要满足以下依赖要求：

- **操作系统**：Linux（推荐 Ubuntu 20.04 或更高版本）
- **编译器**：支持 C++17 的 GCC 或 Clang
- **CMake**：版本 3.10 或更高
- **Python**：版本 3.x（用于运行前端 HTTP 服务器）
- **依赖库和工具**：
  - Boost（system 组件）
  - Crypto++（libcryptopp）
  - TinyXML2
  - Crow（C++ Web 框架，手动安装或通过子模块）

## 安装步骤

以下是在 Linux 系统（如 Ubuntu）上安装依赖和构建项目的步骤。

### 1. 安装系统依赖

更新软件包列表并安装必要的工具和库：

```bash
sudo apt update
sudo apt install -y build-essential cmake g++ libboost-system-dev libcrypto++-dev libtinyxml2-dev python3
```

### 2. 安装 Crow 框架

Crow 框架不在标准软件包仓库中，需要手动安装：

```bash
git clone https://github.com/CrowCpp/crow.git
cd crow
mkdir build && cd build
cmake ..
sudo make install
```

这会将 Crow 的头文件安装到 `/usr/local/include/crow`，库文件安装到 `/usr/local/lib`。

### 3. 克隆项目仓库

克隆 CryptoService 仓库：

```bash
git clone <repository-url>
```

### 4. 构建后端

创建构建目录，使用 CMake 配置项目并编译：

```bash
mkdir build && cd build
cmake ..
make
```

这将生成以下文件：

- `libCryptoCore.so`：密码学功能的共享库。
- `CryptoService`：Web 服务器的可执行文件。

构建产物位于 `build` 目录中。

### 5. 验证配置文件

确保 `config.xml` 文件位于 `build` 目录中，并包含正确的参数：

```xml
<config>
    <affine_a>5</affine_a>
    <affine_b>8</affine_b>
    <rc4_key>secretkey</rc4_key>
    <des_key>8bytekey</des_key>
    <lfsr_seed>1234</lfsr_seed>
</config>
```

## 使用方法

CryptoService 的后端和前端分别运行，前端通过 Python 的 HTTP 服务器提供服务。

### 1. 运行后端服务器

在 `build` 目录中启动 CryptoService 后端服务器：

```bash
cd build
./CryptoService
```

后端服务器默认运行在 `http://127.0.0.1:8080`。

### 2. 运行前端服务器

前端使用 Python 的 `http.server` 模块运行，端口为 8000。进入 `web` 目录并启动服务器：

```bash
cd web
python3 no_cache_server.py
```
no_cache_server.py是无缓存，为了好测试
**注意，需要修改web/script.js中后端地址（修改为自己的虚拟机地址）**


### 3. 访问 Web 界面

在浏览器中打开以下地址：

```
http://<ip>:8000
```

你将看到 CryptoService 的 Web 界面，可以进行以下操作：

- 选择算法（如仿射密码、RC4、RSA 等）。
- 输入明文、密文或消息。
- 执行加密、解密、哈希、签名或密钥交换操作。
- 在浏览器中查看结果。

**注意**：前端会通过 AJAX 请求与后端（`http://127.0.0.1:8080`）通信，确保后端服务器已启动。

### 4. 使用 API

后端提供 RESTful API 端点，可通过 `curl` 或 Postman 等工具进行交互。以下是一些示例：

#### 使用仿射密码加密

```bash
curl -X POST http://127.0.0.1:8080/affine/encrypt \
-H "Content-Type: application/json" \
-d '{"plaintext":"KONGYU","a":3,"b":2}'
```

响应：

```json
{"ciphertext": "GSPUWK"}
```


### 5. 输入输出说明

- **仿射密码**：仅处理字母 (A-Z)，非字母字符保持不变。
- **二进制输出**：RC4、DES、RSA 和 LFSR 等算法产生二进制输出，在 Web 界面中以 Base64 编码显示。
- **错误处理**：无效的 JSON、空的输入或格式错误会返回 400 状态码和错误信息。

## 故障排除

- **后端服务器无法启动**：检查 `build` 目录中的 `config.xml` 是否存在，且依赖库是否正确安装。
- **前端无法加载**：确保在 `web` 目录中运行了 `python3 -m http.server 8000`或者`python3 no_cache_server.py`，并检查浏览器控制台是否有错误。
- **CORS 问题**：后端已配置 CORS 头，允许跨域请求。确保前端请求正确指向 `http://<虚拟机ip>:8080`。
- **库文件未找到**：确认 `libcryptopp`、`libtinyxml2` 和 Boost 库位于 `/usr/lib`，或更新 `LD_LIBRARY_PATH`。
- **端口冲突**：若 8080 或 8000 端口被占用，可修改 `CryptoService.cpp`（后端端口）或 Python 服务器命令（前端端口），然后重新构建。

## 安全提示

- **非生产环境**：此实现使用简化的密码学参数（如小型 RSA 密钥），仅用于教育目的，切勿在生产环境中使用。
- **密钥管理**：`config.xml` 中硬编码的密钥不安全。实际应用中应使用安全的密钥存储机制。
- **弱算法**：RC4 和 DES 因已知漏洞在安全应用中已被弃用。
