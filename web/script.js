// 算法描述
const algorithmDescriptions = {
    affine: "仿射密码：基于模运算的替换密码，仅加密字母 (A-Z)，使用线性变换 (ax + b) mod 26。",
    rc4: "RC4：流密码，生成伪随机字节流，适用于任意文本，输出为二进制 (显示为 Base64)。",
    lfsr_jk: "LFSR + J-K 触发器：自定义流密码，结合线性反馈移位寄存器和触发器，输出为二进制。",
    des: "DES：对称块密码，使用 8 字节密钥，ECB 模式，输出为二进制 (显示为 Base64)。",
    rsa: "RSA：非对称加密，基于大整数分解，公钥加密/私钥解密，输出为二进制。",
    sha1: "SHA-1：哈希算法，生成 160 位摘要，输出为二进制 (显示为 Base64)。",
    signature: "数字签名：使用 RSA 签名 SHA-1 哈希，确保消息完整性和来源，签名输出为 Base64。",
    dh: "D-H 密钥交换：协商共享密钥，附带 RSA 签名验证，输出包含密钥和签名。"
};

// 动态更新表单
const algorithmSelect = document.getElementById('algorithm');
const description = document.getElementById('algorithm-description');
const inputText = document.getElementById('input-text');
const signatureGroup = document.getElementById('signature-group');
const signatureInput = document.getElementById('signature-input');
const dhRoleGroup = document.getElementById('dh-role-group');
const actionPrimary = document.getElementById('action-primary');
const actionSecondary = document.getElementById('action-secondary');
const primarySpinner = document.getElementById('primary-spinner');
const secondarySpinner = document.getElementById('secondary-spinner');
const result = document.getElementById('result');

// 主题切换
const themeToggle = document.getElementById('theme-toggle');
themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('dark-mode');
    themeToggle.innerHTML = document.body.classList.contains('dark-mode')
        ? '<i class="fas fa-sun"></i>'
        : '<i class="fas fa-moon"></i>';
});

algorithmSelect.addEventListener('change', function() {
    const algorithm = this.value;
    const affineGroup = document.getElementById('affine-group'); // 新增获取元素
    
    // 重置界面元素
    result.innerHTML = '';
    result.classList.add('d-none');
    inputText.value = '';
    signatureInput.value = '';
    
    // 更新算法描述
    description.textContent = algorithm ? algorithmDescriptions[algorithm] : '';
    
    // 控制参数组显示（新增仿射密码判断）
    affineGroup.style.display = algorithm === 'affine' ? 'block' : 'none'; // 新增控制
    signatureGroup.style.display = algorithm === 'signature' ? 'block' : 'none';
    dhRoleGroup.style.display = algorithm === 'dh' ? 'block' : 'none';

    // 设置输入框提示文字
    inputText.placeholder = algorithm === 'affine' ? '输入明文或密文（仅限字母和空格）'
        : algorithm === 'sha1' || algorithm === 'signature' || algorithm === 'dh' ? '输入消息'
        : algorithm ? '输入明文或Base64编码的密文' : '输入文本';

    // 更新操作按钮
    if (algorithm === 'sha1') {
        actionPrimary.textContent = '计算哈希';
        actionSecondary.style.display = 'none';
    } else if (algorithm === 'signature') {
        actionPrimary.textContent = '生成签名';
        actionSecondary.textContent = '验证签名';
        actionSecondary.style.display = 'block';
    } else if (algorithm === 'dh') {
        actionPrimary.textContent = '执行密钥交换';
        actionSecondary.style.display = 'none';
    } else if (algorithm === 'affine') {  // 新增仿射密码按钮设置
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

    // 新增仿射密码参数处理
    if (algorithmSelect.value === 'affine') {
        const a = document.getElementById('affine-a').value;
        const b = document.getElementById('affine-b').value;
        // // 添加必要参数验证
        // if (!a || !b) {
        //     result.innerHTML = '<div class="alert alert-warning">请填写仿射密码参数 a 和 b</div>';
        //     result.classList.remove('d-none');
        //     resetButtons();
        //     return;
        // }
        // // 互质检查 (a必须与26互质)
        // if (gcd(numA, 26) !== 1) {
        //     result.innerHTML = `
        //         <div class="alert alert-warning">
        //             参数 a 必须与26互质，当前值 ${numA} 不符合要求<br>
        //             有效值示例：1,3,5,7,9,11,15,17,19,21,23,25
        //         </div>`;
        //     result.classList.remove('d-none');
        //     resetButtons();
        //     return;
        // }
        data = { ...data, a: parseInt(a), b: parseInt(b) };
    }

    fetch(`http://192.168.3.4:8080${url}`, {
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
    const signature = signatureInput.value.trim();
    const dhRole = document.getElementById('dh-role').value;
    const action = e.submitter.id;

    if (!algorithm) {
        result.innerHTML = '<div class="alert alert-warning">请先选择算法</div>';
        result.classList.remove('d-none');
        return;
    }
    if (!input) {
        result.innerHTML = '<div class="alert alert-warning">请输入内容</div>';
        result.classList.remove('d-none');
        return;
    }
    if (algorithm === 'signature' && action === 'action-secondary' && !signature) {
        result.innerHTML = '<div class="alert alert-warning">请输入签名</div>';
        result.classList.remove('d-none');
        return;
    }
    if (algorithm === 'affine') {
        const isValid = /^[A-Za-z\s]*$/.test(input);
        const a = document.getElementById('affine-a').value;
        const b = document.getElementById('affine-b').value;
        
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

    let url, data, isBinaryInput = false, isBinaryOutput = false;
    switch (algorithm) {
        case 'affine':
            url = action === 'action-primary' ? '/affine/encrypt' : '/affine/decrypt';
            data = { [action === 'action-primary' ? 'plaintext' : 'ciphertext']: input.toUpperCase() };
            break;
        case 'rc4':
            url = action === 'action-primary' ? '/rc4/encrypt' : '/rc4/decrypt';
            data = { [action === 'action-primary' ? 'plaintext' : 'ciphertext']: input };
            isBinaryInput = action !== 'action-primary';
            isBinaryOutput = true;
            break;
        case 'lfsr_jk':
            url = action === 'action-primary' ? '/lfsr_jk/encrypt' : '/lfsr_jk/decrypt';
            data = { [action === 'action-primary' ? 'plaintext' : 'ciphertext']: input };
            isBinaryInput = action !== 'action-primary';
            isBinaryOutput = true;
            break;
        case 'des':
            url = action === 'action-primary' ? '/des/encrypt' : '/des/decrypt';
            data = { [action === 'action-primary' ? 'plaintext' : 'ciphertext']: input };
            isBinaryInput = action !== 'action-primary';
            isBinaryOutput = true;
            break;
        case 'rsa':
            url = action === 'action-primary' ? '/rsa/encrypt' : '/rsa/decrypt';
            data = { [action === 'action-primary' ? 'plaintext' : 'ciphertext']: input };
            isBinaryInput = action !== 'action-primary';
            isBinaryOutput = true;
            break;
        case 'sha1':
            url = '/sha1';
            data = { message: input };
            isBinaryOutput = true;
            break;
        case 'signature':
            url = action === 'action-primary' ? '/rsa/sign' : '/rsa/verify';
            data = action === 'action-primary'
                ? { message: input }
                : { message: input, signature };
            isBinaryInput = action !== 'action-primary';
            isBinaryOutput = action === 'action-primary';
            break;
        case 'dh':
            url = '/dh';
            data = { message: input, role: dhRole };
            isBinaryOutput = true;
            break;
        default:
            result.innerHTML = '<div class="alert alert-danger">未知算法</div>';
            result.classList.remove('d-none');
            return;
    }

    sendRequest(url, data, isBinaryInput, isBinaryOutput);
});