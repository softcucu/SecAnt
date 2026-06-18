# lens: resource-realtime — 嵌入式资源 / 实时性失效

配合 `00-methodology.md` 与 `protocol-stack.md` 使用。这个 lens 面向 C/C++ 嵌入式通信产品,关注攻击者通过协议流量、
管理面请求或本地低权限入口触发**固定资源耗尽、任务饥饿、实时性破坏、watchdog 复位或服务离线**。它和 `dos` 有重叠,
但这里更强调嵌入式系统的固定容量、RTOS/任务模型、驱动/中断上下文和长期运行稳定性。

## 一、Bug Patterns
1. **固定资源池耗尽** —— 连接表、会话表、重组缓冲、mbuf/sk_buff、消息块、DMA descriptor、timer、fd/handle、
   socket、work item 等由输入持续占用,没有 per-peer / per-session / global 上限,或错误路径未归还。
2. **任务 / 消息队列堆积** —— 网络包、IPC 消息、事件、workqueue 可被持续 enqueue,消费者处理慢或可被阻塞;
   队列满策略 fail-open、覆盖关键事件、无限重试,导致控制面/数据面饥饿。
3. **watchdog / 心跳 / 保活失效** —— 畸形输入使主循环、协议任务、喂狗线程或 keepalive 处理长时间阻塞;
   喂狗与真实健康状态脱钩,或攻击者可让设备频繁复位、掉线、重新注册。
4. **RTOS task 栈 / 实时预算破坏** —— 递归解析、深嵌套 TLV、大栈数组、长临界区、阻塞 IO/锁等待导致 task 栈溢出、
   deadline miss、周期任务漂移或高优先级任务被低优先级路径拖住。
5. **优先级反转 / 调度饥饿** —— 低优先级任务持有高优先级任务需要的锁/资源且无优先级继承;
   攻击者可制造大量低优先级工作让认证、路由、保活、转发等关键任务拿不到 CPU。
6. **中断 / timer / callback 上下文误用** —— ISR、timer callback、驱动回调里做复杂解析、动态分配、日志 IO、
   锁等待、阻塞调用或长循环,导致中断延迟、丢包、软中断风暴或系统抖动。
7. **重传 / 重组 / 老化机制失效** —— 畸形分片、乱序包、重复包、半开连接、永不完成的协商让重组槽、定时器、
   retransmit 队列或 pending transaction 长期占用。
8. **错误恢复与降级路径耗尽资源** —— 反复 reset/reinit/reconnect、日志风暴、core dump、配置落盘、flash 擦写等
   被输入触发,造成 CPU/IO/flash 寿命或存储空间耗尽。

## 二、Phase-A grep 种子
```
queue|enqueue|dequeue|ring|fifo|workqueue|tasklet|event|message|mailbox|msgq|sem_|semaphore
pool|slab|mempool|mbuf|sk_buff|skb|pbuf|descriptor|dma|timer|timeout|retrans|retry|pending
watchdog|wdt|feed|keepalive|heartbeat|alive|poll|select|epoll|sleep|delay|usleep|msleep
pthread_create|pthread_mutex|pthread_cond|sched_|priority|nice|rtos|task|thread|isr|irq|interrupt
alloca\s*\(|\[[^]]{0,40}(MAX|SIZE|LEN|DEPTH|COUNT)[^]]{0,40}\]   # task 栈大对象/可疑固定数组
while\s*\(\s*1\s*\)|for\s*\(\s*;\s*;\s*\)|for\s*\([^;]+;[^;]*len|while\s*\([^)]*retry
open\s*\(|socket\s*\(|accept\s*\(|close\s*\(|free\s*\(|release|put_|dec_ref|refcnt
```
对每个资源创建/入队/加引用点,反向找释放/出队/减引用点;对每个循环、锁、callback、timer,确认是否可能被不可信输入拉长。

## 三、Common False Positives to avoid
- 资源有严格全局上限和 per-peer / per-session 配额,且超过上限会丢弃或限速,不会阻塞关键任务。
- 队列是固定容量且满时有明确、可接受的丢弃策略;丢弃不会破坏认证、保活、释放或状态收敛。
- 长循环只处理固定小批量或有时间片/yield/watchdog-friendly 设计,并能被攻击者输入约束住上界。
- ISR/timer/callback 只做置位、入队、唤醒等短操作,复杂工作已切到普通任务上下文。
- 锁顺序、优先级继承、超时等待、错误路径释放均可由真实代码证明确实覆盖当前路径。
- 资源泄漏只在进程退出路径发生,且目标不是长期运行服务/daemon/固件任务。

## 四、嵌入式通信产品专项
- 区分**控制面**与**数据面**:数据面高流量是否能饿死控制面认证、路由更新、邻居维护、保活或管理命令。
- 看**半开/未认证状态**:未认证连接、未完成握手、未完成分片重组是否已经占用昂贵资源。
- 看**异常风暴**:畸形报文是否触发日志风暴、告警风暴、重连风暴、flash 频繁写入或 watchdog reset loop。
- 看**长期运行**:单次触发不明显但可累积的 fd、timer、buffer、refcnt、pending transaction 泄漏,在设备长时间运行后会变成 DoS。

## 五、deconfliction(与其他 lens 重叠时归类)
- 根因是未夹紧长度导致越界写/读 → 优先 `memory` / `integer`。
- 根因是无界分配、递归或普通算法复杂度炸弹 → 可归 `dos`;若依赖固定池、任务调度、watchdog、RTOS、ISR 或长期资源回收,归本 lens。
- 根因是锁保护错误导致数据竞争/UAF → 优先 `race`;若主要影响是优先级反转、任务饥饿或 deadline miss,归本 lens。
- 信息被泄露 → `infoleak`;认证状态绕过 → `authn`;本 lens 只报资源/实时性破坏本身可独立成立的漏洞。
