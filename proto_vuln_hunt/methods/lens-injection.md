# lens: injection — 注入 / 路径 / 格式化串 / 反序列化

配合 `00-methodology.md` 使用。

## 一、Bug Patterns
1. **命令注入** —— `system/popen/execl/execlp/execvp`(走 shell 解析)拼接含外部数据;`sh -c "...$var..."`。
2. **路径穿越 / 符号链接** —— 用户控制的路径片段含 `../`、绝对路径、未规范化;`open/fopen/unlink` 前未 `realpath`/未限制根目录;
   解压/写文件时未校验目标路径(zip-slip);跟随符号链接写敏感位置。
3. **格式化字符串** —— `printf/fprintf/snprintf/syslog/err` 等的**格式串含外部数据**(`printf(user)` 而非 `printf("%s", user)`)。
4. **反序列化 / 解析信任** —— 长度/计数/偏移/指针/类型标签**直接信任**,解析时不校验边界与自洽性;
   嵌套深度无限(栈溢出/复杂度炸弹);指针/句柄字段被反序列化后直接解引用。
5. **SQL/LDAP/模板等次级注入**(若代码涉及)。

## 二、Phase-A grep 种子
```
\bsystem\s*\(|\bpopen\s*\(|\bexecl|\bexecv|\bexeclp|\bexecvp|\bsh\s+-c
\bopen\s*\(|\bfopen\s*\(|\bunlink\s*\(|\brename\s*\(|symlink|readlink|realpath
printf\s*\(\s*[a-z_][a-z0-9_]*\s*\)|fprintf\s*\([^,]+,\s*[a-z_][a-z0-9_]*\s*\)|syslog\s*\(   # 格式串疑似变量
snprintf\s*\([^,]+,[^,]+,\s*[a-z_]                                                            # 同上
unmarshal|deserialize|decode|parse_|->\s*offset|->\s*ptr|->\s*type
```
格式化串模式要人工确认第一个/格式位是否为变量。路径类要跟踪片段来源与是否做了规范化与根目录约束。

## 三、Common False Positives to avoid
- exec 走的是 `execve` 且参数数组化(无 shell 解析),且参数非攻击者可控。
- 路径已 `realpath` 规范化并校验仍在允许根目录内;或路径完全由程序内部常量构成。
- 格式串是字符串字面量;变量出现在可变参数位而非格式位。
- 反序列化前对长度/偏移/计数做了完整夹紧与自洽性校验,且嵌套有深度上限。

## 四、协议/管理面专项
- 配置/证书/密钥文件路径若来自远端协商或不可信配置,按攻击者可控处理。
- 把报文里的偏移/指针字段直接当地址用 = 高危类型混淆+注入,务必追溯。
