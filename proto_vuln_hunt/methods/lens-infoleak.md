# lens: infoleak — 信息泄露

配合 `00-methodology.md`(Phase A→B、coverage 纪律、7 段式)使用。
关注点:**机密/内存内容被泄露给攻击者**(而非破坏内存本身——纯内存破坏看 memory)。
威胁价值:直接泄密(密钥/口令/token)、或泄露地址削弱 ASLR 为后续利用铺路。

## 一、Bug Patterns
1. **未初始化内存外泄** —— 栈/堆缓冲或结构体未清零(无 `memset`/`= {0}`/`bzero`)即被整体回传给对端/用户态
   (`memcpy`→`send/write`、`copy_to_user/put_user`、写入响应结构体)。读出的是上次/相邻数据。
2. **结构体 padding 泄露** —— 编译器对齐填充字节天然未初始化;**逐字段赋值**后把**整个 struct** 拷出/外发,
   padding 里残留的栈/堆数据随之泄露(经典内核 infoleak)。`sizeof(struct)` 大于各字段之和即可疑。
3. **越界读回传(heartbleed 式)** —— 回读/回显的长度取自**不可信字段**且未夹紧到实际写入长度,
   `memcpy(out, buf, attacker_len)` 后回传,带出相邻内存。
4. **缓冲区复用残留** —— 复用的发送/响应/临时缓冲未按**本次实际长度**清空或截断,把上次内容带出。
5. **地址/指针泄露(削弱 ASLR)** —— 把指针/栈地址/堆地址/函数地址经日志、错误消息、响应字段、
   `printf("%p")`、断言/崩溃信息泄出,使攻击者推算基址。
6. **敏感数据外泄** —— 密钥/私钥/口令/token/会话 ID/内部路径/配置进**日志**、错误信息、调试/诊断/统计接口、
   崩溃转储(core)、临时文件、环境变量回显。
7. **预言(oracle)式泄露** —— 错误码/返回长度/响应时间随秘密不同而不同,构成可区分预言
   (口令/HMAC/比较的非常量时间见 crypto;这里侧重一般秘密与长度/状态差异)。

## 二、Phase-A grep 种子(在审计范围内 rg,建候选清单)
```
memcpy|memmove|copy_to_user|put_user|\bsend\b|sendto|\bwrite\b|sprintf|snprintf   # 外发/回传点
malloc\(|kmalloc\(|alloca\(                       # 分配后是否紧跟 memset/清零?
memset\(|bzero\(|= *\{ *0? *\}|kzalloc|calloc      # 反查:哪些缓冲“没有”清零
sizeof\s*\(\s*struct|->|\}\s*;                     # 结构体整体拷贝(配合 padding 看)
%p|printf|fprintf|syslog|log\.|LOG|perror|strerror # 地址/敏感数据进日志/错误
key|secret|passwd|password|token|private|nonce|seed # 敏感变量是否被打印/外发
ntohs\(|ntohl\(.*len|->len|->size                  # 回读长度是否取自报文且未夹紧
```
对每个**外发/回传/日志**点回答:写出去的字节**全部都是本次显式写入**的吗?有没有未初始化区、padding、
按可控长度多读的部分?回传长度是否夹紧到 `min(实际写入, 缓冲大小)`?

## 三、Common False Positives to avoid
- 外发前已 `memset`/`= {0}`/`calloc`/`kzalloc` 清零,或逐字节填满了整个外发区(含 padding)。
- 回传长度已夹紧到实际写入长度(`min(len, written)`),不会多读。
- 泄露的是**非敏感/本就公开**的数据(协议常量、已公开字段)。
- 仅写本地日志且日志不可被攻击者读取、也不含敏感内容(确认部署确实如此,别假设)。
- 地址被打印但目标是**调试构建**且发行版已关闭(确认 `#ifdef DEBUG`/日志级别确实生效)。
- 未初始化但**只在本地使用、从不外传**——那是 UB/逻辑问题(归 memory/uninit),不是信息泄露。

## 四、协议栈/管理面专项(另见 protocol-stack.md)
- 响应/ACK/错误报文是否把整个内部结构体(含 padding/未用字段)直接回灌网络。
- 长度/计数回显字段取自请求且未校验 → 回读放大泄露(心脏滴血模式)。
- 认证失败/解析失败路径的错误响应是否区分“用户不存在 vs 口令错误”、或回带内部状态/地址。
