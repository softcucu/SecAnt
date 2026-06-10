# lens: race — 竞态 / TOCTOU / 并发

配合 `00-methodology.md` 使用。

## 一、Bug Patterns
1. **TOCTOU(检查-使用时间差)** —— `access()`→`open()`、`stat()`→`open()`;对共享状态"先检查后动作",其间状态可被改;
   路径名校验后再用(符号链接竞态)。
2. **Double-fetch** —— 对同一不可信输入(用户态/网络缓冲/共享内存)**读两次**:第一次用于校验、第二次用于使用,
   两次值可不一致(典型:先读长度校验,再读长度做拷贝)。
3. **欠锁(under-locking)** —— 共享数据无锁访问;锁释放过早;复合操作只锁了一部分;读写锁粒度错。
4. **过锁/死锁** —— 锁顺序不一致致死锁;非递归锁递归获取。
5. **非线程安全 API** —— 在多线程上下文用了非线程安全函数(strtok、非 `_r` 系列、共享 errno 误用)。
6. **信号安全** —— 信号处理函数里调用非 async-signal-safe 函数;handler 与主流程竞争同一状态;handler 重入。
7. **连接生命周期竞态** —— 半关闭/断开/重连期间的悬垂状态、回调与释放竞争。

## 二、Phase-A grep 种子
```
pthread_mutex|pthread_rwlock|pthread_create|std::mutex|std::thread|atomic|_Atomic|volatile
access\s*\(|stat\s*\(|lstat\s*\(|readlink\s*\(    # 配合随后的 open/write 看 TOCTOU
signal\s*\(|sigaction\s*\(
copy_from_user|get_user|memcpy.*user                # 内核 double-fetch(若适用)
->\s*refcnt|atomic_inc|atomic_dec|refcount
```
对共享数据:谁写、谁读、是否同一把锁全程保护临界区?对不可信输入:是否被读取多次?

## 三、Common False Positives to avoid
- 可证明单线程(且不被信号/回调并发进入)。
- 初始化后只读的不可变数据;TLS 中的变量;一次性启动时写、之后只读。
- 锁覆盖整个临界区且无早释放;使用了原子/内存屏障。
- 能证明同一线程完成两次访问。

## 四、提示
- 竞态 finding 要写清:**共享对象、竞争的两条路径、缺失/不足的同步、可被攻击者拉开窗口的方式**。
- "需要赢竞态"在严重度上降一级,但仍要报(见 00-severity-rubric)。
