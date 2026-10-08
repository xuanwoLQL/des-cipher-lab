/*
 * 实验2  DES 加密算法实验
 * 功能：纯 C 实现经典 DES，支持对任意明文（任意长度、字符串或十六进制）加密和解密，
 *       采用 ECB 模式，最后一组用 PKCS#7 填充。
 *
 * 编译：gcc des.c -o des.exe
 * 运行：des.exe                进入交互模式（1 加密 / 2 解密 / 0 退出）
 *       des.exe -e <密钥> <明文>    加密字符串，输出密文 HEX
 *       des.exe -e <密钥> -x <十六进制明文>
 *       des.exe -d <密钥> <十六进制密文>
 *       （密钥为 8 个字符，或 16 位十六进制串；-n 不填充，-v 打印每轮 L、R）
 */
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>          /* 仅用于把控制台输出代码页设为 UTF-8，正确显示中文 */
#endif

#define MAX_DATA 4096         /* 一次可处理的明文字节数上限 */

/* ==================== 1. DES 置换表（FIPS 46-3，下标从 1 开始） ==================== */
static const int IP[64] = {
    58,50,42,34,26,18,10, 2, 60,52,44,36,28,20,12, 4,
    62,54,46,38,30,22,14, 6, 64,56,48,40,32,24,16, 8,
    57,49,41,33,25,17, 9, 1, 59,51,43,35,27,19,11, 3,
    61,53,45,37,29,21,13, 5, 63,55,47,39,31,23,15, 7
};
static const int IP_INV[64] = {
    40, 8,48,16,56,24,64,32, 39, 7,47,15,55,23,63,31,
    38, 6,46,14,54,22,62,30, 37, 5,45,13,53,21,61,29,
    36, 4,44,12,52,20,60,28, 35, 3,43,11,51,19,59,27,
    34, 2,42,10,50,18,58,26, 33, 1,41, 9,49,17,57,25
};
static const int E[48] = {
    32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9,  8, 9,10,11,12,13,
    12,13,14,15,16,17, 16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32, 1
};
static const int P[32] = {
    16, 7,20,21,29,12,28,17,  1,15,23,26, 5,18,31,10,
     2, 8,24,14,32,27, 3, 9, 19,13,30, 6,22,11, 4,25
};
static const int PC1[56] = {
    57,49,41,33,25,17, 9,  1,58,50,42,34,26,18,
    10, 2,59,51,43,35,27, 19,11, 3,60,52,44,36,
    63,55,47,39,31,23,15,  7,62,54,46,38,30,22,
    14, 6,61,53,45,37,29, 21,13, 5,28,20,12, 4
};
static const int PC2[48] = {
    14,17,11,24, 1, 5,  3,28,15, 6,21,10,
    23,19,12, 4,26, 8, 16, 7,27,20,13, 2,
    41,52,31,37,47,55, 30,40,51,45,33,48,
    44,49,39,56,34,53, 46,42,50,36,29,32
};
/* 每一轮循环左移的位数 */
static const int SHIFT[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

/* S 盒：8 个 S 盒，每个 4 行 16 列 */
static const int S[8][4][16] = {
 {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
  {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
  {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
  {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
 {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
  {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
  {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
  {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
 {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
  {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
  {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
  {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
 {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
  {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
  {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
  {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
 {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
  {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
  {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
  {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
 {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
  {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
  {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
  {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
 {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
  {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
  {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
  {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
 {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
  {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
  {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
  {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
};

/* ==================== 2. 基本运算（按位表示，均为 0/1 数组） ==================== */

/* 按 table 做置换：输入的 n 位 -> 输出的 m 位 */
static void permute(const int *in, const int *table, int m, int *out)
{
    int i;
    for (i = 0; i < m; i++)
        out[i] = in[table[i] - 1];
}

/* 28 位寄存器循环左移 s 位 */
static void rotl(int *k, int n, int s)
{
    int tmp[28];
    int i;
    for (i = 0; i < n; i++)
        tmp[i] = k[(i + s) % n];
    memcpy(k, tmp, n * sizeof(int));
}

/* 字节流 <-> 比特流（高位在前，大端序） */
static void bytes_to_bits(const unsigned char *in, int n, int *bits)
{
    int i, j;
    for (i = 0; i < n; i++)
        for (j = 0; j < 8; j++)
            bits[i * 8 + j] = (in[i] >> (7 - j)) & 1;
}

static void bits_to_bytes(const int *bits, int n, unsigned char *out)
{
    int i, j;
    for (i = 0; i < n; i++) {
        out[i] = 0;
        for (j = 0; j < 8; j++)
            out[i] = (unsigned char)((out[i] << 1) | bits[i * 8 + j]);
    }
}

static void bits_to_hex(const int *bits, int n, char *out)
{
    static const char *H = "0123456789ABCDEF";
    int i, j;
    for (i = 0; i < n / 4; i++) {
        int v = 0;
        for (j = 0; j < 4; j++)
            v = (v << 1) | bits[i * 4 + j];
        out[i] = H[v];
    }
    out[n / 4] = '\0';
}

/* ==================== 3. 子密钥生成（密钥扩展） ==================== */
/* 64 位密钥 -> 16 个 48 位子密钥 K(1)..K(16) */
static void key_schedule(const unsigned char key[8], int subkey[16][48])
{
    int k[64], kp[56], c[28], d[28], cd[56];
    int i;

    bytes_to_bits(key, 8, k);
    permute(k, PC1, 56, kp);                 /* PC-1 置换：64 -> 56（去掉 8 个校验位） */
    memcpy(c, kp, 28 * sizeof(int));         /* C0 */
    memcpy(d, kp + 28, 28 * sizeof(int));    /* D0 */

    for (i = 0; i < 16; i++) {
        rotl(c, 28, SHIFT[i]);               /* 循环左移 LS(i) */
        rotl(d, 28, SHIFT[i]);
        memcpy(cd, c, 28 * sizeof(int));
        memcpy(cd + 28, d, 28 * sizeof(int));
        permute(cd, PC2, 48, subkey[i]);     /* PC-2 置换：56 -> 48，得到 K(i) */
    }
}

/* ==================== 4. 轮函数 F ==================== */
/* F(R, K) = P( S( E(R) xor K ) ) */
static void f_function(const int r[32], const int subkey[48], int out[32])
{
    int er[48], sbox_out[32];
    int i, j, row, col, v;

    permute(r, E, 48, er);                       /* E 扩展：32 -> 48 */
    for (i = 0; i < 48; i++)
        er[i] ^= subkey[i];                      /* 与子密钥异或 */

    for (i = 0; i < 8; i++) {                    /* 8 个 S 盒代换：6 -> 4 */
        row = er[i * 6] * 2 + er[i * 6 + 5];
        col = er[i * 6 + 1] * 8 + er[i * 6 + 2] * 4 + er[i * 6 + 3] * 2 + er[i * 6 + 4];
        v = S[i][row][col];
        for (j = 0; j < 4; j++)
            sbox_out[i * 4 + j] = (v >> (3 - j)) & 1;
    }
    permute(sbox_out, P, 32, out);               /* P 置换：32 -> 32 */
}

/* ==================== 5. DES 单分组加解密 ==================== */
/* decrypt = 0 表示加密（子密钥正序），decrypt = 1 表示解密（子密钥逆序） */
static void des_block(const unsigned char in[8], const int subkey[16][48],
                      unsigned char out[8], int decrypt, int trace)
{
    int bits[64], ip[64], left[32], right[32];
    int prev_l[32], prev_r[32], f[32], tmp[32];
    int i;

    bytes_to_bits(in, 8, bits);
    permute(bits, IP, 64, ip);                       /* 初始置换 IP */
    memcpy(left, ip, 32 * sizeof(int));              /* L0 */
    memcpy(right, ip + 32, 32 * sizeof(int));        /* R0 */

    if (trace) {
        char hx[20];
        bits_to_hex(left, 32, hx);  printf("  L(0)  = %s\n", hx);
        bits_to_hex(right, 32, hx); printf("  R(0)  = %s\n", hx);
    }

    for (i = 0; i < 16; i++) {                       /* 16 轮迭代 */
        const int *k = subkey[decrypt ? 15 - i : i];
        memcpy(prev_l, left, 32 * sizeof(int));
        memcpy(prev_r, right, 32 * sizeof(int));

        f_function(prev_r, k, f);
        memcpy(left, prev_r, 32 * sizeof(int));      /* L(i) = R(i-1) */
        for (int j = 0; j < 32; j++)
            tmp[j] = prev_l[j] ^ f[j];               /* R(i) = L(i-1) xor F(R(i-1),K(i)) */
        memcpy(right, tmp, 32 * sizeof(int));

        if (trace) {
            char hx[20];
            bits_to_hex(left, 32, hx);
            printf("  第%2d轮: L = %s  R = ", i + 1, hx);
            bits_to_hex(right, 32, hx);
            printf("%s\n", hx);
        }
    }

    /* 左右交换（得到 R16 L16），再整体做逆初始置换 IP^-1 */
    memcpy(tmp, right, 32 * sizeof(int));            /* 交换后左半 = R16 */
    memcpy(right, left, 32 * sizeof(int));           /* 交换后右半 = L16 */
    memcpy(left, tmp, 32 * sizeof(int));
    memcpy(ip, left, 32 * sizeof(int));              /* 拼成 64 位：R16 || L16 */
    memcpy(ip + 32, right, 32 * sizeof(int));
    permute(ip, IP_INV, 64, bits);                   /* IP^-1 是 64 位置换，不能拆开做 */
    bits_to_bytes(bits, 8, out);
}

/* ==================== 6. ECB 模式 + PKCS#7 填充 ==================== */
/* pad = 1：按 PKCS#7 填充（任意长度都能加密）；
 * pad = 0：不填充，要求明文长度是 8 的整数倍（便于与官方测试向量逐块比对）。
 * trace = 1 时打印每一轮的 L、R，便于与标准资料逐轮核对。 */
static int ecb_encrypt(const unsigned char *in, int len, const unsigned char key[8],
                       unsigned char *out, int pad, int trace)
{
    int subkey[16][48];
    int n, i, pos = 0;

    key_schedule(key, subkey);
    if (pad && len % 8)                  /* PKCS#7：不足 8 字节时补足 */
        n = len + (8 - len % 8);
    else if (pad)                        /* 恰好整除时再补一整组 */
        n = len + 8;
    else
        n = len;                         /* n 为填充后的总字节数 */

    for (i = 0; i < n / 8; i++) {        /* 按 8 字节一组逐块加密 */
        unsigned char block[8];
        int j;
        for (j = 0; j < 8; j++) {
            int idx = i * 8 + j;
            block[j] = (idx < len) ? in[idx]
                                   : (unsigned char)(n - len);   /* 填充字节的值 = 填充长度 */
        }
        if (trace)
            printf(" 【第 %d 个分组】\n", i + 1);
        des_block(block, subkey, out + pos, 0, trace);
        pos += 8;
    }
    return pos;
}

static int ecb_decrypt(const unsigned char *in, int len, const unsigned char key[8],
                       unsigned char *out, int unpad, int trace)
{
    int subkey[16][48];
    int i, pos = 0, last;

    key_schedule(key, subkey);
    for (i = 0; i < len / 8; i++) {
        if (trace)
            printf(" 【第 %d 个分组】\n", i + 1);
        des_block(in + i * 8, subkey, out + pos, 1, trace);
        pos += 8;
    }
    if (unpad) {                         /* 按 PKCS#7 规则去掉填充 */
        last = out[pos - 1];
        if (last > 0 && last <= 8)
            pos -= last;
    }
    return pos;
}

/* ==================== 7. 辅助打印 ==================== */
static void print_hex(const unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++)
        printf("%02X", buf[i]);
}

/* 把 16 进制字符串转成字节，返回字节数（-1 表示长度非法） */
static int hex_to_bytes(const char *hex, unsigned char *out)
{
    int n = (int)strlen(hex), i;
    if (n % 2)
        return -1;
    for (i = 0; i < n / 2; i++) {
        unsigned int v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1)
            return -1;
        out[i] = (unsigned char)v;
    }
    return n / 2;
}

/* ==================== 9. 输入输出辅助函数 ==================== */

/* 判断字符串是否全部由十六进制字符组成 */
static int all_hex(const char *s)
{
    int i;
    if (s[0] == '\0')
        return 0;
    for (i = 0; s[i]; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f') ||
              (s[i] >= 'A' && s[i] <= 'F')))
            return 0;
    return 1;
}

/* 解析密钥：16 位十六进制，或 8 个字符（8 字节）的字符串 */
static int parse_key(const char *s, unsigned char key[8], int *is_hex)
{
    int n = (int)strlen(s);
    if (n == 16 && all_hex(s)) {          /* 16 位十六进制 -> 8 字节 */
        hex_to_bytes(s, key);
        *is_hex = 1;
        return 0;
    }
    if (n == 8) {                         /* 8 个字符 -> 直接取字节 */
        memcpy(key, s, 8);
        *is_hex = 0;
        return 0;
    }
    return -1;
}

/* 读入一行（去掉行尾换行符），返回 -1 表示输入结束 */
static int read_line(const char *prompt, char *buf, int size)
{
    int n;
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buf, size, stdin) == NULL)
        return -1;
    n = (int)strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        buf[--n] = '\0';
    return 0;
}

/* 判断一段字节是不是可以显示的文本（纯 ASCII 可打印，或合法的 UTF-8） */
static int is_text(const unsigned char *p, int len)
{
    int i = 0;
    while (i < len) {
        unsigned char c = p[i];
        int n, k;
        if (c < 0x80) {
            if (c < 0x20 || c == 0x7F)       /* 控制字符不算文本 */
                return 0;
            i++;
            continue;
        }
        if ((c & 0xE0) == 0xC0)      n = 1;  /* 两字节汉字等 */
        else if ((c & 0xF0) == 0xE0) n = 2;  /* 三字节汉字 */
        else if ((c & 0xF8) == 0xF0) n = 3;  /* 四字节 */
        else return 0;
        if (i + n >= len)
            return 0;
        for (k = 1; k <= n; k++)
            if ((p[i + k] & 0xC0) != 0x80)
                return 0;
        i += n + 1;
    }
    return 1;
}

/* 输出明文：是文本时按字符串显示，同时给出十六进制形式；二进制数据只显示十六进制 */
static void print_plain(const unsigned char *buf, int len)
{
    int i;
    if (is_text(buf, len)) {
        printf(" 明文(字符串) = \"");
        for (i = 0; i < len; i++)
            putchar(buf[i]);
        printf("\"\n");
    }
    printf(" 明文(HEX)    = ");
    print_hex(buf, len);
    printf("\n");
}

/* ==================== 10. 加密 / 解密交互流程 ==================== */
static void do_encrypt_flow(void)
{
    char form[32], padline[32], line[MAX_DATA + 1], keyline[128];
    unsigned char key[8], ct[MAX_DATA + 8], pt[MAX_DATA + 8];
    int is_hex, mode, n, ct_len, pt_len, pad;

    printf("\n---- 加密任意明文 ----\n");
    if (read_line(" 明文形式（1=字符串/UTF-8，2=十六进制串）: ", form, sizeof(form)) < 0)
        return;
    mode = atoi(form);
    if (read_line(" 填充方式（1=PKCS#7 填充，默认；2=不填充，长度须为 8 的倍数）: ",
                  padline, sizeof(padline)) < 0)
        return;
    pad = (atoi(padline) == 2) ? 0 : 1;
    if (read_line(" 请输入明文: ", line, MAX_DATA + 1) < 0)
        return;

    if (mode == 2) {                       /* 十六进制明文 */
        if (!all_hex(line)) {
            printf(" 输入不是合法的十六进制串。\n");
            return;
        }
        n = hex_to_bytes(line, pt);
        if (n <= 0) {
            printf(" 十六进制长度必须是偶数。\n");
            return;
        }
    } else {                               /* 字符串明文，按 UTF-8 字节处理 */
        n = (int)strlen(line);
        memcpy(pt, line, n);
    }
    if (n <= 0) {
        printf(" 明文不能为空。\n");
        return;
    }
    if (!pad && n % 8 != 0) {
        printf(" 选择不填充时，明文长度必须是 8 的整数倍（当前 %d 字节）。\n", n);
        return;
    }

    if (read_line(" 请输入密钥（16 位十六进制 或 8 个字符）: ", keyline, sizeof(keyline)) < 0)
        return;
    if (parse_key(keyline, key, &is_hex) < 0) {
        printf(" 密钥不合法：应为 16 位十六进制串或 8 个字符。\n");
        return;
    }
    printf(" 密钥 K = ");
    print_hex(key, 8);
    printf("%s\n", is_hex ? "        （按十六进制解释）" : "    （按 8 字节字符串解释）");

    ct_len = ecb_encrypt(pt, n, key, ct, pad, 0);   /* 按 8 字节分组加密 */
    if (pad)
        printf(" 明文长度 = %d 字节，PKCS#7 填充后 = %d 字节（%d 个分组）\n",
               n, ct_len, ct_len / 8);
    else
        printf(" 明文长度 = %d 字节（不填充，共 %d 个分组）\n", n, ct_len / 8);
    printf(" 密文(HEX) = ");
    print_hex(ct, ct_len);
    printf("\n");

    pt_len = ecb_decrypt(ct, ct_len, key, pt, pad, 0);   /* 顺手解密一次，验证可逆 */
    printf(" 用同一密钥解密验证：\n");
    print_plain(pt, pt_len);
}

static void do_decrypt_flow(void)
{
    char line[MAX_DATA + 1], keyline[128];
    unsigned char key[8], ct[MAX_DATA + 8], pt[MAX_DATA + 8];
    int is_hex, n, pt_len;

    printf("\n---- 解密任意密文 ----\n");
    if (read_line(" 请输入密文(HEX，长度为 16 的整数倍): ", line, MAX_DATA + 1) < 0)
        return;
    if (!all_hex(line)) {
        printf(" 输入不是合法的十六进制串。\n");
        return;
    }
    n = hex_to_bytes(line, ct);
    if (n <= 0 || n % 8 != 0) {
        printf(" 密文长度必须是 16 的整数倍（即 8 字节分组的整数倍）。\n");
        return;
    }
    if (read_line(" 请输入密钥（16 位十六进制 或 8 个字符）: ", keyline, sizeof(keyline)) < 0)
        return;
    if (parse_key(keyline, key, &is_hex) < 0) {
        printf(" 密钥不合法：应为 16 位十六进制串或 8 个字符。\n");
        return;
    }

    pt_len = ecb_decrypt(ct, n, key, pt, 1, 0);
    printf(" 密钥 K = ");
    print_hex(key, 8);
    printf("%s\n", is_hex ? "        （按十六进制解释）" : "    （按 8 字节字符串解释）");
    printf(" 密文长度 = %d 字节（%d 个分组），去除 PKCS#7 填充后明文长度 = %d 字节\n",
           n, n / 8, pt_len);
    print_plain(pt, pt_len);
}

/* ==================== 11. 交互模式 与 命令行 ==================== */
static void print_usage(const char *prog)
{
    printf("用法：\n");
    printf("  %s                              进入交互模式（1 加密 / 2 解密 / 0 退出）\n", prog);
    printf("  %s -e <密钥> <明文>              加密字符串明文，输出密文 HEX\n", prog);
    printf("  %s -e <密钥> -x <16进制明文>      加密十六进制数据\n", prog);
    printf("  %s -d <密钥> <16进制密文>         解密密文，输出明文\n", prog);
    printf("  可选参数（写在 -e/-d 之后）：\n");
    printf("    -x <16进制>   以十六进制形式给出数据（密文必须用这种形式）\n");
    printf("    -n            不填充，要求长度为 8 字节的整数倍，便于与标准测试向量比对\n");
    printf("    -v            打印 16 轮的 L、R 中间值，便于与标准资料逐轮核对\n");
    printf("  密钥：8 个字符（8 字节），或 16 位十六进制串。\n");
    printf("  提示：命令行参数中的中文可能受系统编码影响，建议在交互模式下输入中文，\n");
    printf("        或用 -x 以十六进制形式传入（例如 UTF-8 编码的中文）。\n");
}

static void interactive(void)
{
    char line[64];
    for (;;) {
        printf("\n=================== DES 加解密工具 ===================\n");
        printf(" 1. 加密任意明文（字符串或十六进制，长度不限）\n");
        printf(" 2. 解密任意密文（十六进制）\n");
        printf(" 0. 退出\n");
        printf("======================================================\n");
        if (read_line(" 请选择: ", line, sizeof(line)) < 0)
            break;
        if (line[0] == '1')
            do_encrypt_flow();
        else if (line[0] == '2')
            do_decrypt_flow();
        else if (line[0] == '0' || line[0] == 'q' || line[0] == 'Q')
            break;
        else
            printf(" 输入无效，请重新选择。\n");
    }
}

/* ==================== 12. 主程序 ==================== */
int main(int argc, char *argv[])
{
#ifdef _WIN32
    SetConsoleOutputCP(65001);      /* 控制台按 UTF-8 输出，避免中文乱码 */
    SetConsoleCP(65001);            /* 输入也按 UTF-8 读取，可直接输入中文 */
#endif
    if (argc == 1) {                /* 无参数：交互模式 */
        interactive();
        return 0;
    }
    if (argc >= 4 && argv[1][0] == '-' && (argv[1][1] == 'e' || argv[1][1] == 'd')) {
        unsigned char key[8], buf[MAX_DATA + 8], out[MAX_DATA + 8];
        int is_hex = 0, n = 0, len, i;
        int hex_data = 0, nopad = 0, verbose = 0, have_key = 0, have_data = 0;
        int decrypt_mode = (argv[1][1] == 'd');   /* 解密时数据一定是十六进制密文 */

        /* 解析 -x / -n / -v 等开关，其余第一个参数当密钥、第二个当数据 */
        for (i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "-x")) { hex_data = 1; continue; }
            if (!strcmp(argv[i], "-n")) { nopad = 1; continue; }
            if (!strcmp(argv[i], "-v")) { verbose = 1; continue; }
            if (!have_key) {
                if (parse_key(argv[i], key, &is_hex) < 0) {
                    printf("密钥不合法：应为 16 位十六进制串或 8 个字符。\n");
                    return 1;
                }
                have_key = 1;
                continue;
            }
            if (!have_data) {
                if (hex_data || decrypt_mode) {
                    if (!all_hex(argv[i]) || (n = hex_to_bytes(argv[i], buf)) <= 0) {
                        printf("十六进制数据不合法。\n");
                        return 1;
                    }
                } else {
                    n = (int)strlen(argv[i]);
                    memcpy(buf, argv[i], n);
                }
                have_data = 1;
            }
        }
        if (!have_key || !have_data) {
            print_usage(argv[0]);
            return 1;
        }
        printf("密钥 K = ");
        print_hex(key, 8);
        printf("%s\n", is_hex ? "（按十六进制解释）" : "（按 8 字节字符串解释）");

        if (!decrypt_mode) {                           /* 加密 */
            if (nopad && n % 8 != 0) {
                printf("不填充时数据长度必须是 8 的整数倍（当前 %d 字节）。\n", n);
                return 1;
            }
            len = ecb_encrypt(buf, n, key, out, nopad ? 0 : 1, verbose);
            printf("明文字节数 = %d，密文分组数 = %d\n", n, len / 8);
            printf("密文(HEX) = ");
            print_hex(out, len);
            printf("\n");
        } else {                                        /* 解密 */
            if (n % 8) {
                printf("密文长度必须是 8 字节的整数倍。\n");
                return 1;
            }
            len = ecb_decrypt(buf, n, key, out, nopad ? 0 : 1, verbose);
            printf("密文分组数 = %d，明文字节数 = %d\n", n / 8, len);
            print_plain(out, len);
        }
        return 0;
    }
    print_usage(argv[0]);
    return 1;
}
