# lens: crypto — 密码算法误用(设计层)

配合 `00-methodology.md` 使用。重在密码学**用法**正确性,而非实现本身的边信道(除非明显)。

## 一、Bug Patterns
1. **弱/过时算法** —— MD5/SHA1 用于签名或防篡改;DES/3DES/RC4;可被协商降级到弱套件/导出级;自研加密。
2. **分组模式误用** —— ECB;固定/可预测 IV;CTR/GCM 的 nonce 重用(同密钥同 nonce = 灾难);CBC 可被 padding oracle。
3. **完整性缺失** —— 只加密不认证(无 MAC/AEAD),密文可被篡改;MAC-then-encrypt / encrypt-and-MAC 误序;
   只校验长度不校验 MAC;校验 MAC 用非常量时间比较。
4. **密钥/IV/nonce 管理** —— 密钥硬编码/落日志;IV 从可预测源(计数器/时间)派生用于需随机 IV 的模式;
   密钥重用跨用途;弱 KDF / 无盐 / 迭代次数过低。
5. **随机数源弱** —— `rand()/random()/srand(time())/`非 CSPRNG 用于密钥、IV、nonce、会话、challenge。
6. **证书/主机名校验** —— 校验被关闭(`SSL_VERIFY_NONE`、`InsecureSkipVerify`、`CURLOPT_SSL_VERIFYPEER=0`);
   不校验主机名;信任任意 CA;不校验链/有效期/吊销;接受自签。
7. **签名验证缺陷** —— 验签返回值未检查;接受 `alg=none`;只解析不验签;可被替换为弱算法。

## 二、Phase-A grep 种子
```
\bMD5|\bSHA1\b|\bDES\b|RC4|ECB|\bRSA_|\bDH_
EVP_|AES_|HMAC|CMAC|GCM|CBC|CTR|EVP_EncryptInit|EVP_aes_
\bIV\b|nonce|iv\s*=|memset\s*\([^,]*iv|RAND_bytes|rand\s*\(|srand\s*\(|random\s*\(
SSL_VERIFY_NONE|VERIFY_PEER|verify_mode|InsecureSkip|SSL_CTX_set_verify|X509_verify
PEM_read|d2i_|hardcode|0x[0-9a-f]{16,}                # 疑似硬编码密钥
KDF|PBKDF2|bcrypt|scrypt|argon2|salt
```

## 三、Common False Positives to avoid
- MD5/SHA1 仅用于非安全用途(校验和、缓存键、去重),非签名/防篡改。
- IV 用 `RAND_bytes`/CSPRNG 生成且每次不同;nonce 有严格不重用保证。
- 关闭证书校验仅出现在测试/调试代码且不进生产路径(去核实)。
- 用了经过验证的 AEAD(AES-GCM/ChaCha20-Poly1305)且 nonce 管理正确。

## 四、严重度提示
完整性缺失(可篡改)、可降级到弱套件、证书校验关闭通常 HIGH;影响认证/密钥的误用按 00-severity-rubric 升一级。
