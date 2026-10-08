# (0)des.c——DES 加密算法程序代码解释

主要代码存放位置
```
des.c   ← 全程序唯一源文件（约 620 行，纯 C 实现经典 DES）
des.exe ← 编译出的可执行文件
```

整体架构 → 调用链 → 逐块拆解 → 关键知识点 → 运行方式 → 易错点

## 1. 整体架构

一个用纯 C 从头实现的**经典 DES 加密算法**，核心知识点是：

- **DES 的完整流程**：IP 初始置换 → 16 轮 Feistel 迭代 → 左右交换 → IP⁻¹ 逆置换
- **Feistel 轮函数 F**：E 扩展 → 与子密钥异或 → 8 个 S 盒代换 → P 置换
- **子密钥生成**：PC-1 去校验位 → 循环左移 → PC-2 压缩置换
- **工作模式与填充**：ECB 模式 + PKCS#7 填充（也支持不填充模式去比对标准测试向量）

整个文件按注释分成 12 个模块：

| 模块 | 包含内容 | 作用 |
|---|---|---|
| 1. DES 置换表 | IP / IP_INV / E / P / PC1 / PC2 / SHIFT / S 盒 | FIPS 46-3 标准查表数据 |
| 2. 基本运算 | `permute` / `rotl` / `bytes_to_bits` / `bits_to_bytes` / `bits_to_hex` | 位运算基础工具 |
| 3. 子密钥生成 | `key_schedule` | 64 位密钥 → 16 个 48 位子密钥 |
| 4. 轮函数 F | `f_function` | F(R, K) = P(S(E(R) ⊕ K)) |
| 5. 单分组加解密 | `des_block` | 一个 8 字节分组走完整个 DES 流程 |
| 6. ECB + 填充 | `ecb_encrypt` / `ecb_decrypt` | 多分组处理 + PKCS#7 |
| 7. 辅助打印 | `print_hex` / `hex_to_bytes` | HEX 输出与解析 |
| 9. 输入输出辅助 | `all_hex` / `parse_key` / `read_line` / `is_text` / `print_plain` | 密钥解析、中文识别、文本/HEX 显示 |
| 10. 加解密交互流程 | `do_encrypt_flow` / `do_decrypt_flow` | 交互模式下的向导式输入 |
| 11. 交互模式与命令行 | `print_usage` / `interactive` | 菜单与用法说明 |
| 12. 主程序 | `main` | 交互模式 / 命令行模式分发 |

一句话总结：**标准查表（模块1）→ 位运算工具（模块2）→ 按 DES 规范拼装（模块3~5）→ 多分组与填充（模块6）→ 让人用得舒服的外壳（模块7~12）。**

## 2. 调用链全景图

```
main(argc, argv)
  │
  ├─ 无参数 ────────────────► interactive()            ← 交互菜单
  │                            ├─ do_encrypt_flow()    ← 加密向导
  │                            │    └─ ecb_encrypt() → key_schedule() + des_block()
  │                            └─ do_decrypt_flow()    ← 解密向导
  │                                 └─ ecb_decrypt() → key_schedule() + des_block()
  │
  └─ 有参数（-e/-d 命令行）───► 解析 -x/-n/-v 开关 → 加密或解密分支
                                   ├─ ecb_encrypt() / ecb_decrypt()
                                   └─ print_plain() → is_text()

DES 单分组流程（des_block，最核心的一条链）：
  8 字节明文
    │  bytes_to_bits()：字节 → 64 位比特
    ▼
  IP 初始置换（打乱位置）
    │
    ▼
  L0 = 左 32 位，R0 = 右 32 位
    │
    ▼  重复 16 轮：
  L(i) = R(i-1)
  R(i) = L(i-1) ⊕ F(R(i-1), K(i))     ← Feistel 结构，加密解密共用同一套，只是子密钥顺序相反
    │
    ▼
  左右交换（得到 R16 || L16）
    │
    ▼
  IP⁻¹ 逆置换 → bits_to_bytes() → 8 字节密文

F 轮函数内部（f_function）：
  R(32位) ──E扩展──► 48位 ──⊕ 子密钥K(48位)──► 分成8组(每组6位)
      ──► 8个S盒代换(6→4) ──► 32位 ──P置换──► 输出(32位)
```

## 3. 逐块拆解

### 3.1 模块 1：DES 置换表（第 21~92 行）

这些表全部来自 DES 标准（FIPS 46-3），**下标从 1 开始**（而 C 数组下标从 0 开始，所以 `permute` 里取数时都写了 `table[i] - 1`）：

```
第22行
static const int IP[64] = { 58,50,42,34,26,18,10,2, ... };
```
- **IP 初始置换**：把 64 位明文按固定顺序重排。第 1 位来自原第 58 位，第 2 位来自原第 50 位……
- 目的是打乱相邻位，让相邻 8 位的字节结构在后续轮中"扩散"。

```
第28行
static const int IP_INV[64] = { 40,8,48,16,56,24,64,32, ... };
```
- **IP⁻¹ 逆置换**：加密的最后一步，把 IP 的打乱还原回去。`IP` 和 `IP_INV` 是**互逆**的两张表——按 IP 打乱后，再按 IP_INV 就能还原。

```
第34行
static const int E[48] = { 32,1,2,3,4,5, 4,5,6,7,8,9, ... };
```
- **E 扩展置换**：把 32 位 R 扩展成 48 位。注意首尾重复：第 1 位取 R 的第 32 位，第 48 位取 R 的第 1 位。
- 为什么扩展？为了和 48 位子密钥异或；同时让相邻 S 盒共享输入位，加快"雪崩效应"（一位明文变化，很快扩散到整个密文）。

```
第39行
static const int P[32] = { 16,7,20,21,29,12,28,17, ... };
```
- **P 置换**：S 盒输出后再打乱一次，把 8 个 S 盒的输出位混合，避免"某个 S 盒的输出只影响局部"。

```
第43行
static const int PC1[56] = { 57,49,41,33,25,17,9, ... };
第49行
static const int PC2[48] = { 14,17,11,24,1,5, ... };
```
- **PC-1**：64 位密钥 → 56 位，**去掉 8 个校验位**（每字节第 8 位，DES 密钥奇偶校验用，不参与加密）。
- **PC-2**：56 位 → 48 位，进一步压缩选取，生成每一轮的 48 位子密钥。

```
第56行
static const int SHIFT[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
```
- 每轮子密钥生成前，C、D 两半各自循环左移的位数：第 1、2、9、16 轮移 1 位，其余移 2 位。**这个"移几位"也是标准规定的**，不是随便定的。

```
第59行
static const int S[8][4][16] = { {...}, {...}, ... };
```
- **8 个 S 盒**，每个是 4 行 × 16 列的表，这是 DES 里**唯一的非线性部件**（安全性的核心，代换表是精心设计防差分/线性攻击的）。
- 输入 6 位：第 1 位 + 第 6 位拼成行号（0~3），中间 4 位拼成列号（0~15），查表得到 0~15 的值，转成 4 位二进制输出。

### 3.2 模块 2：基本运算（第 94~144 行）

```
第97行
static void permute(const int *in, const int *table, int m, int *out)
{
    int i;
    for (i = 0; i < m; i++)
        out[i] = in[table[i] - 1];
}
```
- **一个函数实现所有置换**（IP、IP_INV、E、P、PC1、PC2 全用它）。`table[i] - 1` 就是把表里的 1 基下标转成 C 的 0 基下标。
- 这也是为什么整个文件只有这一个置换函数——**查表驱动的设计**。

```
第105行
static void rotl(int *k, int n, int s)   /* 28 位寄存器循环左移 s 位 */
{
    int tmp[28];
    for (i = 0; i < n; i++)
        tmp[i] = k[(i + s) % n];
    memcpy(k, tmp, n * sizeof(int));
}
```
- 循环左移：第 `i` 位的新值来自第 `(i+s) % n` 位，`% n` 实现"绕回"。
- 子密钥生成里 C、D 各 28 位，各移各的位。

```
第115行  bytes_to_bits：字节 → 比特流（高位在前）
第123行  bits_to_bytes：比特流 → 字节
第133行  bits_to_hex：比特流 → 十六进制字符串
```
- DES 全程在"位"上运算，所以要先做这个转换。`(in[i] >> (7 - j)) & 1`：取出第 j 位（大端序，最高位在前）。
- `bits_to_hex` 每 4 位拼成一个 16 进制字符（`H[v]` 查表），用于打印中间值方便核对。

### 3.3 模块 3：子密钥生成（第 146~165 行）

```
第148行
static void key_schedule(const unsigned char key[8], int subkey[16][48])
{
    bytes_to_bits(key, 8, k);
    permute(k, PC1, 56, kp);                 /* 64 -> 56，去掉 8 个校验位 */
    memcpy(c, kp, 28 * sizeof(int));         /* C0 = 前 28 位 */
    memcpy(d, kp + 28, 28 * sizeof(int));    /* D0 = 后 28 位 */

    for (i = 0; i < 16; i++) {
        rotl(c, 28, SHIFT[i]);               /* 每轮先循环左移 */
        rotl(d, 28, SHIFT[i]);
        memcpy(cd, c, 28 * sizeof(int));     /* 拼回 56 位 */
        memcpy(cd + 28, d, 28 * sizeof(int));
        permute(cd, PC2, 48, subkey[i]);     /* 56 -> 48，得到 K(i) */
    }
}
```
流程：`密钥(64位) --PC-1--> 56位 --拆两半(C0|D0)--> 每轮先左移再拼回 --PC-2--> 48位子密钥`。
- 16 轮生成 16 个 48 位子密钥，存进 `subkey[16][48]` 数组供加解密复用。
- **加密用正序 K1..K16，解密用逆序 K16..K1**（在 `des_block` 里通过 `subkey[decrypt ? 15 - i : i]` 实现），这就是 DES 加密解密共用一个 `des_block` 函数的秘诀。

### 3.4 模块 4：轮函数 F（第 167~186 行）

```
第169行
static void f_function(const int r[32], const int subkey[48], int out[32])
{
    permute(r, E, 48, er);                       /* ① E 扩展：32 -> 48 */
    for (i = 0; i < 48; i++)
        er[i] ^= subkey[i];                      /* ② 与子密钥异或 */

    for (i = 0; i < 8; i++) {                    /* ③ 8 个 S 盒：6 -> 4 */
        row = er[i * 6] * 2 + er[i * 6 + 5];     /* 行号 = 第1位×2 + 第6位 */
        col = er[i * 6 + 1] * 8 + er[i * 6 + 2] * 4
            + er[i * 6 + 3] * 2 + er[i * 6 + 4]; /* 列号 = 中间4位 */
        v = S[i][row][col];
        for (j = 0; j < 4; j++)
            sbox_out[i * 4 + j] = (v >> (3 - j)) & 1;  /* 4 位结果 */
    }
    permute(sbox_out, P, 32, out);               /* ④ P 置换：32 -> 32 */
}
```
- 公式：`F(R, K) = P(S(E(R) ⊕ K))`，每一步都对应上面的代码行。
- 行号计算：`er[i*6]*2 + er[i*6+5]`——把第 1 位当高位、第 6 位当低位拼成 0~3。
- 列号计算：中间 4 位按二进制权值拼成 0~15。
- S 盒输出是 0~15 的整数，再按位拆回 4 个 0/1。

### 3.5 模块 5：单分组加解密（第 188~236 行）—— 整个 DES 的心脏

```
第190行
static void des_block(const unsigned char in[8], const int subkey[16][48],
                      unsigned char out[8], int decrypt, int trace)
{
    bytes_to_bits(in, 8, bits);
    permute(bits, IP, 64, ip);                       /* ① IP 初始置换 */
    memcpy(left, ip, 32 * sizeof(int));              /* ② L0、R0 各 32 位 */
    memcpy(right, ip + 32, 32 * sizeof(int));

    for (i = 0; i < 16; i++) {                       /* ③ 16 轮 Feistel 迭代 */
        const int *k = subkey[decrypt ? 15 - i : i]; /* 解密 = 子密钥逆序 */
        memcpy(prev_l, left, 32 * sizeof(int));
        memcpy(prev_r, right, 32 * sizeof(int));

        f_function(prev_r, k, f);
        memcpy(left, prev_r, 32 * sizeof(int));      /* L(i) = R(i-1) */
        for (int j = 0; j < 32; j++)
            tmp[j] = prev_l[j] ^ f[j];               /* R(i) = L(i-1) ⊕ F(R(i-1),K(i)) */
        memcpy(right, tmp, 32 * sizeof(int));
    }

    /* ④ 左右交换：得到 R16 || L16（注意 DES 最后不交换是它的经典坑） */
    memcpy(tmp, right, 32 * sizeof(int));
    memcpy(right, left, 32 * sizeof(int));
    memcpy(left, tmp, 32 * sizeof(int));
    memcpy(ip, left, 32 * sizeof(int));
    memcpy(ip + 32, right, 32 * sizeof(int));
    permute(ip, IP_INV, 64, bits);                   /* ⑤ IP⁻¹ 逆置换 */
    bits_to_bytes(bits, 8, out);
}
```
关键点：
- **加密和解密是同一个函数**：唯一的区别是子密钥取逆序（`decrypt ? 15 - i : i`）。这正是 Feistel 结构的对称性——解密就是加密倒着跑。
- **第 16 轮结束后的左右交换不能省**：DES 标准设计为"最后一轮不交换、输出 R16||L16"，所以代码里显式交换一次再拼装。漏掉这一步会导致解密对不上——这是实现 DES 最经典的 bug。
- `trace` 参数：为 1 时打印 L(0)、R(0) 和每轮的 L、R（16 进制），方便与标准资料逐轮核对，这是实验报告里"逐轮中间值"的出处。

### 3.6 模块 6：ECB 模式 + PKCS#7 填充（第 238~291 行）

```
第242行
static int ecb_encrypt(const unsigned char *in, int len, const unsigned char key[8],
                       unsigned char *out, int pad, int trace)
{
    key_schedule(key, subkey);
    if (pad && len % 8)              n = len + (8 - len % 8);   /* 不足 8 字节，补到 8 的倍数 */
    else if (pad)                    n = len + 8;               /* 恰好整除，再补一整组 */
    else                             n = len;                   /* 不填充 */

    for (i = 0; i < n / 8; i++) {    /* 逐 8 字节分组 */
        ...
        block[j] = (idx < len) ? in[idx] : (unsigned char)(n - len);  /* 填充字节值 = 填充长度 */
        des_block(block, subkey, out + pos, 0, trace);
        pos += 8;
    }
    return pos;
}
```
- **ECB 模式**：每个 8 字节分组独立加密，分组之间没有关联（简单，但相同明文块会得到相同密文块）。
- **PKCS#7 填充规则**：缺 n 字节就补 n 个值为 n 的字节；如果明文恰好是 8 的倍数，**也要补一整组 8 个 0x08**——这样解密时才能区分"原样数据"和"填充数据"。
- `block[j] = (idx < len) ? in[idx] : (n - len)`：前 `len` 字节是真实数据，后面全填"填充长度"。

```
第272行
static int ecb_decrypt(const unsigned char *in, int len, const unsigned char key[8],
                       unsigned char *out, int unpad, int trace)
{
    ...
    for (i = 0; i < len / 8; i++)
        des_block(in + i * 8, subkey, out + pos, 1, trace);   /* decrypt=1，子密钥逆序 */
    ...
    if (unpad) {
        last = out[pos - 1];          /* 最后一个字节就是填充长度 */
        if (last > 0 && last <= 8)    /* 合法性检查，防恶意密文 */
            pos -= last;              /* 去掉填充 */
    }
    return pos;
}
```
- 去填充：PKCS#7 的特性——**最后一个字节的值就是填充长度**，直接读出来减去即可。
- `last > 0 && last <= 8` 的合法性检查：防止非法密文算出荒谬的填充长度。

### 3.7 模块 7 & 9：辅助函数（第 293~402 行）

```
第302行  hex_to_bytes：HEX 字符串 → 字节数组（奇数长度返回 -1）
第319行  all_hex：判断字符串是否全由 0-9/a-f/A-F 组成
第332行  parse_key：密钥解析 —— 16 位 HEX 按字节解，8 个字符直接取字节
第349行  read_line：读一行并去掉行尾 \n / \r
```
- `parse_key` 是输入的统一入口：**16 位十六进制（如 "133457799BBCDFF1"）或 8 个字符（如 "abcdefgh"）都能当密钥**，通过 `is_hex` 标记告诉调用方怎么显示。

```
第363行
static int is_text(const unsigned char *p, int len)   /* 判断是不是可显示文本 */
```
- 自己实现了一个 UTF-8 校验器：ASCII 可打印字符通过；`0xC0` 开头是两字节、`0xE0` 开头是三字节（汉字）、`0xF0` 开头是四字节，并检查后续字节都是 `10xxxxxx` 格式。
- **为什么要这个？** 解密出的结果可能是"文本"也可能是"二进制数据"。是文本就按字符串打印，否则只显示 HEX，避免把乱码打到屏幕上。

```
第390行
static void print_plain(const unsigned char *buf, int len)   /* 输出明文 */
```
- 文本：同时打印字符串形式和 HEX 形式；非文本：只打印 HEX。

### 3.8 模块 10~12：交互与命令行（第 404~617 行）

```
第405行  do_encrypt_flow：加密向导
   选择明文形式（1=字符串/UTF-8，2=十六进制）→ 选择填充方式 → 输明文 → 输密钥
   → ecb_encrypt 加密 → 顺手 ecb_decrypt 一次验证可逆 → 打印结果
第470行  do_decrypt_flow：解密向导
   输密文(HEX，长度须为 16 的整数倍) → 输密钥 → ecb_decrypt → 去填充 → 打印
第521行  interactive：主菜单循环（1 加密 / 2 解密 / 0 退出）
```
- 交互模式里所有输入都走 `read_line`，支持直接输中文（配合 `main` 里的 `SetConsoleOutputCP(65001)` / `SetConsoleCP(65001)` 把控制台切成 UTF-8）。
- 加密向导最后**自动解密一次验证**——这是程序的自测，证明算法可逆。

```
第544行
int main(int argc, char *argv[])
{
#ifdef _WIN32
    SetConsoleOutputCP(65001);      /* 输出按 UTF-8，避免中文乱码 */
    SetConsoleCP(65001);            /* 输入按 UTF-8，可直接输中文 */
#endif
    if (argc == 1) { interactive(); return 0; }          /* 无参数 → 菜单 */
    if (argc >= 4 && argv[1][0]=='-' && (argv[1][1]=='e'||argv[1][1]=='d')) {
        ... 解析 -x / -n / -v，第一个参数当密钥，第二个当数据 ...
        if (!decrypt_mode) { ecb_encrypt(...) }          /* -e：加密 */
        else               { ecb_decrypt(...) }          /* -d：解密 */
    }
    print_usage(argv[0]);
    return 1;
}
```
- 命令行模式：`-e <密钥> <明文>` / `-e <密钥> -x <16进制明文>` / `-d <密钥> <16进制密文>`。
- `-n` 不填充（要求长度是 8 的倍数，便于和官方测试向量逐块比对）、`-v` 打印每轮 L、R。
- **Windows 下用 `SetConsoleOutputCP(65001)` 是中文实验报告能显示中文的关键**——否则控制台用 GBK 代码页输出 UTF-8 字节会乱码。

## 4. 关键知识点速查表

| 知识点 | 出现位置 | 一句话 |
|---|---|---|
| 查表驱动置换 | `permute` | 一个函数 + 一堆表实现 IP/IP_INV/E/P/PC1/PC2 |
| 1 基下标 → 0 基下标 | 所有 `permute` 调用 | 表里是 1~64，C 数组是 0~63，取数要 `-1` |
| Feistel 结构 | `des_block` | 每轮 `R(i)=L(i-1)⊕F(R(i-1),K(i))`，加密解密共用 |
| 子密钥逆序解密 | `des_block` 第 209 行 | `subkey[decrypt ? 15-i : i]`，解密即倒跑加密 |
| E 扩展 | `f_function` | 32→48 位，首尾复制，配合异或与扩散 |
| S 盒非线性代换 | `f_function` | 6 位进 4 位出，行=首尾位，列=中间 4 位；DES 安全性核心 |
| PC-1 去校验位 | `key_schedule` | 64 位密钥 → 56 位，每字节第 8 位不参与加密 |
| 循环左移位数表 | `SHIFT[16]` | 第 1/2/9/16 轮移 1 位，其余移 2 位（标准规定） |
| 最后一轮左右交换 | `des_block` 第 228 行 | 输出 R16||L16 再 IP⁻¹，漏掉解密必错 |
| ECB 模式 | `ecb_encrypt/decrypt` | 每分组独立加密，简单但相同明文块密文相同 |
| PKCS#7 填充 | `ecb_encrypt` | 缺 n 补 n 个 n；整除也要补一整组；末字节=填充长度 |
| 大端序比特流 | `bytes_to_bits` | `(b >> (7-j)) & 1`，最高位在前 |
| UTF-8 合法性判断 | `is_text` | 手工校验 2/3/4 字节编码，区分文本与二进制 |
| 控制台代码页 | `main` | `SetConsoleOutputCP(65001)` 让中文不乱码 |
| 可逆性自测 | `do_encrypt_flow` | 加密后顺手解密一次，证明算法闭环 |

## 5. 运行方式

```
gcc des.c -o des.exe

des.exe                        # 进入交互模式（1 加密 / 2 解密 / 0 退出）
des.exe -e <密钥> <明文>         # 加密字符串，输出密文 HEX
des.exe -e <密钥> -x <16进制明文> # 加密十六进制数据
des.exe -d <密钥> <16进制密文>    # 解密
可选开关（写在 -e/-d 之后）：
  -n   不填充（长度须为 8 字节整数倍，便于与标准测试向量比对）
  -v   打印 16 轮 L、R 中间值，便于逐轮核对
密钥：8 个字符，或 16 位十六进制串（如 133457799BBCDFF1）
```
命令行传中文可能受系统编码影响——所以程序提示：交互模式输中文，或中文用 UTF-8 的 HEX 形式传。

## 6. 易错点 / 设计要点（实现 DES 最容易踩的坑）

| 坑 | 现象 | 根因与解法 |
|---|---|---|
| 忘记最后一轮左右交换 | 加密能跑但解密还原不了 | DES 输出的是 R16||L16 而不是 L16||R16；代码第 228~233 行显式交换，注释专门标了 |
| 表下标忘了 -1 | 置换结果完全错乱 | 表是 1 基，C 数组 0 基；`permute` 统一处理 |
| 解密用正序子密钥 | 解出乱码 | 解密必须逆序 `subkey[15-i]` |
| 长度不是 8 倍数直接加密 | 越界或结果不完整 | ECB 必须按 8 字节分组；`ecb_encrypt` 里 `n` 是填充后长度，循环按 `n/8` 走 |
| PKCS#7 只补不填满 | 恰好 8 字节时解密去不掉填充 | 整除也要补一整组 0x08（代码第 251~252 行专门处理） |
| 去填充不检查 | 非法密文算出荒谬长度 | `last > 0 && last <= 8` 合法性判断 |
| Windows 中文乱码 | 输出"锟斤拷" | 控制台代码页默认 GBK，`SetConsoleOutputCP(65001)` 切 UTF-8 |
| 把二进制当字符串打印 | 屏幕出现乱码控制字符 | `is_text` 先判断，非文本只输出 HEX |

> 一句话理解整个程序：**模块 1 的表 + 模块 2 的工具 + 模块 3~6 的拼装，就是 DES 的全部算法本体；模块 7~12 是让它能"输中文、出 HEX、逐轮可核对、可交互可命令行"的工程外壳。** 实验报告里的"标准向量比对""逐轮中间值"分别对应 `-n` 不填充模式和 `-v` 打印模式。
