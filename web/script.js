// 算法描述
const algorithmDescriptions = {
    affine: "仿射密码：基于模运算的替换密码，仅加密字母 (A-Z)，使用线性变换 (ax + b) mod 26。\n\n" +
            "原理：将每个字母映射到数字（A=0, B=1, ..., Z=25），然后应用函数 E(x) = (ax + b) mod 26，其中 a 与 26 互质。\n" +
            "解密使用函数 D(y) = a⁻¹(y - b) mod 26，其中 a⁻¹ 是 a 在模 26 下的乘法逆元。\n" +
            "本实现中，使用 mod_inverse 函数计算乘法逆元，仅处理字母字符，保留空格和其他字符不变。",
            
    rc4: "RC4：流密码，生成伪随机字节流，适用于任意文本，输出为二进制 (显示为 Base64)。\n\n" +
         "原理：RC4 使用可变长度的密钥（通常为 40-2048 位）初始化一个 256 字节的状态向量 S，然后生成伪随机字节流与明文进行异或操作。\n" +
         "本实现使用 CryptoPP 库的 ARC4 类，处理过程包括：\n" +
         "1. 使用密钥初始化状态向量 S\n" +
         "2. 生成与明文等长的密钥流\n" +
         "3. 将密钥流与明文/密文进行异或操作\n" +
         "加密和解密操作相同，因为异或操作具有自反性。",
         
    lfsr_jk: "LFSR + J-K 触发器：自定义流密码，结合线性反馈移位寄存器和触发器，输出为二进制。\n\n" +
             "原理：该算法结合了线性反馈移位寄存器(LFSR)和J-K触发器的特性：\n" +
             "1. LFSR：使用4位寄存器，反馈多项式为 x⁴ + x + 1（位0和位3异或）\n" +
             "2. J-K触发器：使用LFSR状态的位0和位1作为J和K输入\n" +
             "3. 每生成8位密钥流后，与明文/密文的一个字节进行异或\n" +
             "该算法是对称的，加密和解密过程相同，只要使用相同的种子值。",
             
    des: "DES：对称块密码，使用 8 字节密钥，ECB 模式，输出为二进制 (显示为 Base64)。\n\n" +
         "原理：DES(数据加密标准)是一种分组密码，处理64位(8字节)数据块，使用56位有效密钥(通常表示为8字节)。\n" +
         "加密过程：\n" +
         "1. 初始置换(IP)：对输入的64位块进行重排\n" +
         "2. 16轮Feistel网络：每轮使用子密钥进行替换和置换操作\n" +
         "3. 最终置换(IP⁻¹)：对结果进行最后的重排\n\n" +
         "本实现使用CryptoPP库的DES类，采用ECB(电子密码本)模式，每个块独立加密，没有使用初始化向量。\n" +
         "注意：ECB模式对于相同的明文块会产生相同的密文块，在实际应用中通常不推荐使用。",
         
    rsa: "RSA：非对称加密，基于大整数分解，公钥加密/私钥解密，输出为二进制。\n\n" +
         "原理：RSA基于大整数因子分解的计算困难性，使用一对密钥：公钥(e,n)和私钥(d,n)。\n" +
         "密钥生成：\n" +
         "1. 选择两个质数p和q（本实现中使用p=101, q=103）\n" +
         "2. 计算n = p×q（模数）和φ(n) = (p-1)×(q-1)（欧拉函数）\n" +
         "3. 选择公钥指数e，满足gcd(e,φ(n))=1（本实现中e=7）\n" +
         "4. 计算私钥指数d，满足e×d ≡ 1 (mod φ(n))\n\n" +
         "加密：c = m^e mod n（m为明文数值，c为密文数值）\n" +
         "解密：m = c^d mod n\n\n" +
         "本实现中，每个字符单独加密，结果存储为2字节（因为n<2^16），使用mod_exp函数进行模幂运算。",
         
    dh: "D-H 密钥交换：使用RSA私钥加密DH公钥并签名，协商共享密钥。请填写正确的RSA私钥来验证你的身份!(d=8743,n=10403)\n\n" +
        "原理：Diffie-Hellman密钥交换允许双方在不安全的通道上协商共享密钥。本实现结合了DH和RSA：\n" +
        "1. 使用固定的DH参数：素数p=997和生成元g=2\n" +
        "2. 客户端生成随机私钥a，计算公钥A = g^a mod p\n" +
        "3. 客户端使用RSA私钥(d,n)对公钥A进行加密，并对A的MD5哈希进行签名\n" +
        "4. 服务器验证签名，使用自己的私钥b计算共享密钥s = A^b mod p\n" +
        "5. 客户端可以计算相同的共享密钥s = B^a mod p\n\n" +
        "本实现中，服务器使用固定的私钥b=123，客户端需要提供正确的RSA私钥(d=8743,n=10403)进行身份验证。"
};

// 动态更新表单
const algorithmSelect = document.getElementById('algorithm');
const description = document.getElementById('algorithm-description');
const inputTextGroup = document.getElementById('input-text-group');
const inputText = document.getElementById('input-text');
const affineGroup = document.getElementById('affine-group');
const affineA = document.getElementById('affine-a');
const affineB = document.getElementById('affine-b');
const dhGroup = document.getElementById('dh-group');
const rsaD = document.getElementById('rsa-d');
const rsaN = document.getElementById('rsa-n');
const actionPrimary = document.getElementById('action-primary');
const actionSecondary = document.getElementById('action-secondary');
const primarySpinner = document.getElementById('primary-spinner');
const secondarySpinner = document.getElementById('secondary-spinner');
const result = document.getElementById('result');
const keyGroup = document.getElementById('key-group');
const keyInput = document.getElementById('key-input');

// 主题切换
const themeToggle = document.getElementById('theme-toggle');
themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('dark-mode');
    themeToggle.innerHTML = document.body.classList.contains('dark-mode')
        ? '<i class="fas fa-sun"></i>'
        : '<i class="fas fa-moon"></i>';
});

// 模幂运算
function mod_exp(base, exp, mod) {
    let result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 === 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp = Math.floor(exp / 2);
    }
    return result;
}

// RSA 加密（使用私钥加密）
function rsa_encrypt(message, d, n) {
    let ciphertext = '';
    for (let i = 0; i < message.length; i++) {
        let m = message.charCodeAt(i);
        let c = mod_exp(m, d, n);
        ciphertext += String.fromCharCode((c >> 8) & 0xFF) + String.fromCharCode(c & 0xFF);
    }
    return btoa(ciphertext);
}

algorithmSelect.addEventListener('change', function() {
    const algorithm = this.value;
    
    // 重置界面元素
    result.innerHTML = '';
    result.classList.add('d-none');
    inputText.value = '';
    affineA.value = '';
    affineB.value = '';
    rsaD.value = '';
    rsaN.value = '';
    keyInput.value = '';
    
    // 更新算法描述
    if (algorithm) {
        description.textContent = algorithmDescriptions[algorithm];
        description.style.display = 'block';
    } else {
        description.textContent = '';
        description.style.display = 'none';
    }
    
    // 控制参数组显示
    inputTextGroup.style.display = 1;
    affineGroup.style.display = algorithm === 'affine' ? 'block' : 'none';
    dhGroup.style.display = algorithm === 'dh' ? 'block' : 'none';
    inputTextGroup.style.display = algorithm === 'dh' ? 'none' : 'block';
    keyGroup.style.display = ['rc4', 'lfsr_jk', 'des'].includes(algorithm) ? 'block' : 'none';

    // 动态管理 required 属性
    const needKey = ['rc4', 'lfsr_jk', 'des'].includes(algorithm);
    keyInput.required = needKey;
    inputText.required = algorithm !== 'dh' && algorithm !== 'signature';
    affineA.required = algorithm === 'affine';
    affineB.required = algorithm === 'affine';
    rsaD.required = algorithm === 'dh';
    rsaN.required = algorithm === 'dh';

    // 设置输入框提示文字
    if (algorithm !== 'dh') {
        inputText.placeholder = algorithm === 'affine' ? '输入明文或密文（仅限字母和空格）'
            : algorithm ? '输入明文或Base64编码的密文' : '输入文本';
    }

    // 更新操作按钮
    if (algorithm === 'dh') {
        actionPrimary.textContent = '执行密钥交换';
        actionSecondary.style.display = 'none';
    } else if (algorithm === 'affine') {
        actionPrimary.textContent = '加密';
        actionSecondary.textContent = '解密';
        actionSecondary.style.display = 'block';
    } else if (algorithm) {
        actionPrimary.textContent = '加密';
        actionSecondary.textContent = '解密';
        actionSecondary.style.display = 'block';
    } else {
        actionPrimary.textContent = '执行';
        actionSecondary.style.display = 'none';
    }
});

// 发送 API 请求
function sendRequest(url, data, isBinaryInput = false, isBinaryOutput = false) {
    console.log(`Sending request to ${url} with data:`, data);
    primarySpinner.classList.remove('d-none');
    secondarySpinner.classList.remove('d-none');
    actionPrimary.disabled = true;
    actionSecondary.disabled = true;

    if (algorithmSelect.value === 'affine') {
        const a = document.getElementById('affine-a').value;
        const b = document.getElementById('affine-b').value;
        data = { ...data, a: parseInt(a), b: parseInt(b) };
    }

    fetch(`http://192.168.4.4:8080${url}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    })
    .then(response => {
        console.log(`Response status: ${response.status}, Headers:`, response.headers);
        if (!response.ok) {
            return response.text().then(text => {
                throw new Error(`API 错误: ${response.status} ${response.statusText}, Body: ${text}`);
            });
        }
        return response.json();
    })
    .then(data => {
        console.log('Received data:', data);
        result.innerHTML = '<h6 class="mb-3">结果:</h6>';
        for (const [key, value] of Object.entries(data)) {
            const displayValue = value;
            result.innerHTML += `
                <div class="mb-2">
                    <strong class="text-capitalize">${key.replace('_', ' ')}:</strong>
                    <code class="d-block p-2 rounded">${displayValue}</code>
                </div>`;
        }
        result.classList.remove('d-none');
        resetButtons();
    })
    .catch(error => {
        console.error('Fetch error:', error);
        result.innerHTML = `<div class="alert alert-danger">错误: ${error.message}</div>`;
        result.classList.remove('d-none');
        resetButtons();
    });
}

function resetButtons() {
    primarySpinner.classList.add('d-none');
    secondarySpinner.classList.add('d-none');
    actionPrimary.disabled = false;
    actionSecondary.disabled = false;
}

// 表单提交
document.getElementById('crypto-form').addEventListener('submit', function(e) {
    e.preventDefault();
    const algorithm = algorithmSelect.value;
    const input = inputText.value.trim();
    const action = e.submitter.id;
    let key; // 新增密钥变量

    // 错误处理部分新增密钥验证
    if (!algorithm) {
        result.innerHTML = '<div class="alert alert-warning">请先选择算法</div>';
        result.classList.remove('d-none');
        return;
    }

    // 新增密钥必填验证
    if (['rc4', 'lfsr_jk', 'des'].includes(algorithm)) {
        key = keyInput.value.trim();
        if (!key) {
            result.innerHTML = '<div class="alert alert-warning">请输入密钥</div>';
            result.classList.remove('d-none');
            return;
        }
    }

    if (algorithm !== 'dh' && inputText.required && !input) {
        result.innerHTML = '<div class="alert alert-warning">请输入内容</div>';
        result.classList.remove('d-none');
        return;
    }

    if (algorithm === 'affine') {
        const isValid = /^[A-Za-z\s]*$/.test(input);
        const a = affineA.value;
        const b = affineB.value;
        
        if (!isValid) {
            result.innerHTML = '<div class="alert alert-warning">仿射密码仅支持字母和空格</div>';
            result.classList.remove('d-none');
            return;
        }
        if (!a || !b) {
            result.innerHTML = '<div class="alert alert-warning">请填写参数 a 和 b</div>';
            result.classList.remove('d-none');
            return;
        }
    }

    if (algorithm === 'dh') {
        const d = rsaD.value;
        const n = rsaN.value;
        if (!d || !n) {
            result.innerHTML = '<div class="alert alert-warning">请填写RSA私钥 d 和 n</div>';
            result.classList.remove('d-none');
            return;
        }
    }

    let url, data, isBinaryInput = false, isBinaryOutput = false;
    switch (algorithm) {
        case 'affine':
            url = action === 'action-primary' ? '/affine/encrypt' : '/affine/decrypt';
            data = { [action === 'action-primary' ? 'plaintext' : 'ciphertext']: input.toUpperCase() };
            break;
        case 'rc4':
            url = action === 'action-primary' ? '/rc4/encrypt' : '/rc4/decrypt';
            data = { 
                [action === 'action-primary' ? 'plaintext' : 'ciphertext']: input,
                key: key  // 新增密钥参数
            };
            isBinaryInput = action !== 'action-primary';
            isBinaryOutput = true;
            break;
        case 'lfsr_jk':
            url = action === 'action-primary' ? '/lfsr_jk/encrypt' : '/lfsr_jk/decrypt';
            data = { 
                [action === 'action-primary' ? 'plaintext' : 'ciphertext']: input,
                key: key  // 新增密钥参数
            };
            isBinaryInput = action !== 'action-primary';
            isBinaryOutput = true;
            break;
        case 'des':
            url = action === 'action-primary' ? '/des/encrypt' : '/des/decrypt';
            data = { 
                [action === 'action-primary' ? 'plaintext' : 'ciphertext']: input,
                key: key  // 新增密钥参数
            };
            isBinaryInput = action !== 'action-primary';
            isBinaryOutput = true;
            break;
        case 'rsa':
            url = action === 'action-primary' ? '/rsa/encrypt' : '/rsa/decrypt';
            data = { 
                [action === 'action-primary' ? 'plaintext' : 'ciphertext']: input 
            };
            isBinaryInput = action !== 'action-primary';
            isBinaryOutput = true;
            break;
        case 'dh':
            const d = rsaD.value;
            const n = rsaN.value;
            const p = 997, g = 2;
            const private_key = Math.floor(Math.random() * (p - 2)) + 1;
            const public_key = mod_exp(g, private_key, p);
            const encrypted_public_key = rsa_encrypt(String(public_key), d, n);
            const hash = CryptoJS.MD5(String(public_key)).toString(CryptoJS.enc.Latin1); // 16 字节二进制
            const signature = rsa_encrypt(hash, d, n);
            console.log("public_key_str:", String(public_key));
            console.log("hash hex:", CryptoJS.MD5(String(public_key)).toString(CryptoJS.enc.Hex));
            url = '/dh';
            data = { encrypted_public_key, signature };
            isBinaryOutput = true;
            break;
        default:
            result.innerHTML = '<div class="alert alert-danger">未知算法</div>';
            result.classList.remove('d-none');
            return;
    }

    sendRequest(url, data, isBinaryInput, isBinaryOutput);
});
