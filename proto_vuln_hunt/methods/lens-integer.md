# lens: integer — 整型溢出 / 截断 / 类型混淆

配合 `00-methodology.md` 使用。核心动作:在每个关注表达式处**解析宽度、符号、类型身份**(读 typedef/macro/struct)。

## 一、Bug Patterns
1. **算术溢出 → 欠分配/越界** —— `a*b`、`n*sizeof(t)`、`len+hdr`、`a+b` 溢出后用作 `malloc/calloc/memcpy` 的大小或循环上界。
2. **宽度截断** —— 64 位值赋给 32 位变量;`(short)len`、`(uint16_t)`;读 64 位但比较/校验只用低 32 位,再按 64 位使用("integer cut")。
3. **符号问题** —— 有符号/无符号混合比较;负值当大无符号用(`int len = -1` → `size_t`);`int` 用在该用 `size_t` 处;`unsigned >= 0` 恒真。
4. **隐式转换** —— 整型提升/降级出乎意料;整数与指针互转。
5. **负值取绝对值溢出** —— `abs(INT_MIN)`、`-(-INT_MIN)` 仍为负。
6. **网络字节序后未夹紧** —— `ntohl/ntohs/be32toh/ntohll` 解出长度/偏移/计数后,**未做上下界检查**就用于分配/索引/拷贝。
7. **类型混淆** —— `union`/`void*`/tag 字段不可信即按某型解释;C 风格强转或 `reinterpret_cast` 到不兼容类型;
   `container_of` 误用;反序列化中由攻击者控制的类型标签决定解释方式;cast 到比实际分配更大的 struct(Struct vs Struct2、`Large*`)。

## 二、Phase-A grep 种子
```
\*\s*sizeof|sizeof\s*\([^)]*\)\s*\*|\bcalloc\s*\(|\bmalloc\s*\([^)]*\*    # size*count 分配
\b(int|short|long|ssize_t|off_t|int[0-9]+_t)\b[^;=]*=[^;]*[-+*]           # 有符号算术产生大小
\b(size_t|uint|ushort|uint[0-9]+_t)\b[^;=]*=[^;]*-                        # 无符号减法(回绕)
ntohl|ntohs|ntohll|be32toh|be16toh|be64toh|
\((unsigned\s+)?(char|short|int|long)\s*\)|\(size_t\)|\(uint[0-9]+_t\)     # 整型强转
reinterpret_cast|static_cast|\(\s*\w+\s*\*\s*\)|\bunion\b|->\s*type\b|\.type\b
```
为命中的表达式建一张 `expr -> 宽度 x 符号` 小表,跨模式复用,别重复读同一 typedef。

## 三、Common False Positives to avoid
- 溢出前有显式检查(`if (a > SIZE_MAX - b)`、`__builtin_*_overflow`、SafeInt)。
- 操作数是常量或已验证的小值(`argc*4`、`sizeof(x)*小常量`)。
- 故意回绕:哈希、校验和、密码学常用有意溢出。
- `unsigned >= 0` 恒真但非安全 bug。
- 已知边界的循环计数(`for(i=0;i<100;i++)`)。

## 四、deconfliction(与其他 lens 重叠时归类)
- 若"溢出"才是 bug 根因(越界/欠分配)→ 归 integer;若只是表达式被误读 → 看 memory。
- 若根因是"坏的强转"→ 归 type-confusion(仍在本 lens 报)。
