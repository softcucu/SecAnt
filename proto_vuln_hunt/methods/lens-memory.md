# lens: memory — 内存破坏

配合 `00-methodology.md`(Phase A→B、coverage 纪律、7 段式)使用。

## 一、Bug Patterns
1. **堆/栈缓冲区溢出** —— `memcpy/memmove/strcpy/strcat/sprintf/snprintf/read/recv` 的长度或目标缓冲外部可控;
   off-by-one(`<=` vs `<`、`len+1`);栈数组下标越界;`alloca`/VLA 长度可控致栈耗尽。
2. **Use-After-Free** —— free 后经悬垂指针访问;错误路径提前 free 后正常路径继续用;悬垂回调/链表节点;
   引用计数配对错误(加减不匹配、归零未释放/未归零仍释放)。
3. **Double-Free** —— 同一指针释放两次;析构与手动 free 重复;错误处理与正常处理都 free。
4. **OOB 读写** —— 数组/指针算术越界;负偏移;循环边界用了可控值;flexible array member(尾随数据)未按长度字段校验。
5. **未初始化内存** —— 结构体/缓冲未清零即使用或回传(信息泄露);部分初始化后整体使用。
6. **任意指针释放 / 部分释放** —— free 非堆内存或未初始化指针;只 free 结构体字段未 free 结构体(或反之)。
7. **realloc 误用** —— `p = realloc(p, n)` 失败时丢原指针致泄露;realloc 后旧指针/别名继续用。

## 二、Phase-A grep 种子(在审计范围内 rg,建候选清单)
```
memcpy|memmove|memset|bcopy|strcpy|strncpy|strcat|strncat|sprintf|snprintf|vsnprintf
\balloca\s*\(|\[\s*\w+\s*\]\s*;        # VLA / 栈数组
\bfree\s*\(|\bdelete\b|kfree\s*\(
realloc\s*\(
->\s*len|->\s*size|->\s*count|\blength\b   # 结构体里的长度字段(配合拷贝看)
\brecv\s*\(|\bread\s*\(|recvfrom\s*\(      # 收包写缓冲
```
对每个拷贝/分配站点,问:长度来自哪里?是否外部可控?目标缓冲多大?有无 `len <= sizeof(buf)` 之类夹紧?

## 三、Common False Positives to avoid
- 拷贝前已显式校验长度(`if (len > sizeof(buf)) return;`)且校验确实覆盖此路径。
- 长度来自 `sizeof(常量)` / 编译期常量 / 已验证的小值。
- free 后立即置 NULL 且后续有 NULL 检查;指针 free 后在使用前已重新赋值为新分配。
- 智能指针/RAII/pool 分配器管理的生命周期(确认确实如此)。
- 静态/全局存储的指针不会因作用域退出而悬垂。

## 四、协议栈专项(另见 protocol-stack.md)
- TLV/分片重组里 `memcpy(dst+off, src, len)`:`off`、`len` 是否都来自报文且未校验上界、是否会重叠/超出 dst。
- `while(len--)` / `len-1` 当 `len==0` 时下溢成超大值再用作拷贝长度。
