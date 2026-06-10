# lens: dos — 拒绝服务(含协议设计 / 空口 DoS)

配合 `00-methodology.md` 使用。DoS 不止"内存耗尽",更重协议**设计/实现缺陷**导致的崩溃与挂死。

## 一、Bug Patterns
1. **空口 / 未认证单包 DoS** —— 单个**未认证或畸形报文**即可使服务崩溃或挂死:畸形长度/标志/类型字段触发
   断言失败、空指针解引用、除零、数组越界 panic、无限循环。这是协议栈最常见且最危险的 DoS。
2. **无界资源消耗** —— 由输入决定的无界分配(`malloc(attacker_len)`);无界循环;放大攻击(小输入大响应/大计算)。
3. **算法复杂度炸弹** —— 嵌套/重复字段导致 O(n²)+;哈希碰撞;正则回溯(ReDoS);解析深度无限递归致栈溢出。
4. **状态/连接/内存耗尽** —— 无上限的会话表/重组缓冲/定时器/半开连接;每包分配不回收。
5. **死锁/活锁** —— 协议状态机被诱导进入互锁或卡死;重传/重组风暴。
6. **整型下溢循环** —— `while(len--)`、`len-1`、`for(i=0;i<len;...)` 当 `len==0` 或为负(无符号回绕)时变成超长/无限循环。
7. **资源泄漏** —— 错误路径不 free / 不 close fd / 不释放连接,长期运行耗尽。

## 二、Phase-A grep 种子
```
assert\s*\(|abort\s*\(|BUG_ON|panic|__builtin_unreachable
malloc\s*\(|calloc\s*\(|realloc\s*\(                       # 看 size 是否来自报文
while\s*\(\s*1\s*\)|for\s*\(\s*;\s*;\s*\)|while\s*\([^)]*--|while\s*\([^)]*len
recursion|recurse|\bdepth\b|parse_.*parse_                  # 递归解析
->\s*len|->\s*count|->\s*size|ntohs|ntohl                   # 报文长度/计数字段驱动循环或分配
/\s*\w+|%\s*\w+                                              # 除零候选(除数可控?)
```
对每个分配/循环/递归:问"输入能否把它推到无界/崩溃?有没有上限夹紧?"

## 三、Common False Positives to avoid
- 分配/循环有已验证上界(`if (n > MAX) return`);固定块流式处理。
- 代码路径不可由不可信输入到达(去证实)。
- 有外部速率限制/系统 ulimit(但**应用层无界**通常仍值得报为设计缺陷)。
- 断言只在 debug 构建启用且生产不触发(去核实编译开关)。

## 四、严重度提示
空口/未认证单包崩溃在 REMOTE 下至少 HIGH(可靠则 HIGH);难触发或需特殊条件的降为 MEDIUM(见 00-severity-rubric)。
