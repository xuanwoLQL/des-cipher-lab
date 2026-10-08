# -*- coding: utf-8 -*-
"""绘制《实验2 DES加密算法实验报告》用的 DES 加密算法流程图。

图形内容严格按 des.c 的实现来画：
    主流程（des_block）      ：IP → L(0)/R(0) → 16 轮迭代 → 交换左右 → IP-1 → 密文
    轮函数（f_function）     ：E 扩展 → 与子密钥异或 → 8 个 S 盒代换 → P 置换
    密钥扩展（key_schedule） ：PC-1 → C(0)/D(0) → 循环左移 LS(i) → PC-2 → K(i)
    分组与填充（ecb_encrypt）：明文按 8 字节分组，末组用 PKCS#7 填充
    解密                    ：流程与加密相同，子密钥按 K(16)…K(1) 逆序使用

画完后会自动做版面检查：方框之间、文字与方框、文字与文字、文字与连线都不允许重叠，
另外还会检查字体缺字（缺字会被渲染成方框 □），有问题会打印出来；NO_OVERLAP 表示版面没有问题。

用法：py 2.py [输出目录]      生成 图1 DES加密算法流程图.png
"""

import math
import os
import sys

from PIL import Image, ImageDraw, ImageFont

FONT_PATH = r"C:\Windows\Fonts\simhei.ttf"
FONT_BOLD = r"C:\Windows\Fonts\msyhbd.ttc"

W, H = 1420, 1040                      # 画布尺寸
BG = "white"
PROC_FILL, PROC_LINE = "#E8F1FB", "#2F6FB2"      # 主流程（蓝）
TERM_FILL, TERM_LINE = "#E7F6EA", "#3E9E58"      # 起止（绿）
KEY_FILL, KEY_LINE = "#F4ECFB", "#7B4FB2"        # 密钥扩展（紫）
NOTE_FILL, NOTE_LINE = "#F5F5F5", "#8C8C8C"      # 说明（灰）
TEXT = "#1F1F1F"

BOXES, TEXTS, SEGS = [], [], []        # 版面检查用：方框、框外文字、连线
PROBLEMS = []


def font(size, bold=False):
    return ImageFont.truetype(FONT_BOLD if bold else FONT_PATH, size)


F_TITLE = font(30, bold=True)
F_BOX = font(20)
F_SMALL = font(18)
F_NOTE = font(16)


def text_size(draw, text, fnt, spacing=6):
    """返回多行文字的宽、高（像素），用于版面计算。"""
    lines = text.split("\n")
    width = max(draw.textlength(ln, font=fnt) for ln in lines)
    ascent, descent = fnt.getmetrics()
    height = len(lines) * (ascent + descent) + (len(lines) - 1) * spacing
    return width, height


def wrap(draw, text, fnt, max_w):
    """按宽度对中文文本做简单换行。"""
    out = []
    for para in text.split("\n"):
        cur = ""
        for ch in para:
            if draw.textlength(cur + ch, font=fnt) > max_w and cur:
                out.append(cur)
                cur = ch
            else:
                cur += ch
        out.append(cur)
    return "\n".join(out)


def rect_of(cx, cy, w, h):
    return (cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2)


def add_box(rect, name):
    BOXES.append((rect[0], rect[1], rect[2], rect[3], name))


def _glyph_pixels(fnt, ch):
    """把单个字符渲染到一张小灰度图上，返回像素字节，用于比较字形。"""
    size = max(fnt.size * 3, 32)
    img = Image.new("L", (size, size), 0)
    ImageDraw.Draw(img).text((0, 0), ch, font=fnt, fill=255)
    return img.tobytes()


def check_glyphs(fnt, text, tag=""):
    """检测字体中缺失的字符（缺字会被渲染成方框 □）。"""
    ref = _glyph_pixels(fnt, "\uE123")   # 私用区字符，任何字体都必定没有
    for ch in sorted(set(text)):
        if ch in "\n\r\t ":
            continue
        if _glyph_pixels(fnt, ch) == ref:
            PROBLEMS.append("字体缺字（会显示成方框）：%r  位置：%s" % (ch, tag))


def process(draw, cx, cy, w, text, name, fnt=F_BOX, fill=PROC_FILL,
            line=PROC_LINE, pad=16, min_h=54):
    """圆角矩形节点：高度按文字自动计算，保证文字不会溢出方框。"""
    wrapped = wrap(draw, text, fnt, w - 2 * pad)
    tw, th = text_size(draw, wrapped, fnt)
    h = max(min_h, th + 2 * pad)
    rect = rect_of(cx, cy, w, h)
    draw.rounded_rectangle(rect, radius=10, fill=fill, outline=line, width=3)
    draw.multiline_text((cx, cy), wrapped, font=fnt, fill=TEXT,
                        anchor="mm", align="center", spacing=6)
    add_box(rect, name or text[:6])
    check_glyphs(fnt, wrapped, name or text[:6])
    if tw > w - 2 * pad + 1 or th > h - 2 * pad + 1:
        PROBLEMS.append("文字溢出方框：%s" % text[:12])
    return rect


def terminal(draw, cx, cy, w, h, text, name, fnt=F_BOX,
             fill=TERM_FILL, line=TERM_LINE):
    rect = rect_of(cx, cy, w, h)
    draw.ellipse(rect, fill=fill, outline=line, width=3)
    draw.text((cx, cy), text, font=fnt, fill=TEXT, anchor="mm")
    add_box(rect, name)
    check_glyphs(fnt, text, name)
    tw, th = text_size(draw, text, fnt)
    if tw > w - 24 or th > h - 16:
        PROBLEMS.append("文字溢出起止框：%s" % text)
    return rect


def label(draw, x, y, text, fnt=F_SMALL, anchor="mm", color="#333333"):
    """框外文字标注，登记外接矩形用于重叠检查。"""
    tw, th = text_size(draw, text, fnt)
    if anchor == "mm":
        x0, y0 = x - tw / 2, y - th / 2
    elif anchor == "lm":
        x0, y0 = x, y - th / 2
    elif anchor == "rm":
        x0, y0 = x - tw, y - th / 2
    else:
        x0, y0 = x, y
    draw.text((x, y), text, font=fnt, fill=color, anchor=anchor)
    TEXTS.append((x0, y0, x0 + tw, y0 + th, text))
    check_glyphs(fnt, text, "标注：" + text)


def line(draw, p1, p2, color="#333333", width=3, head=True):
    """画连线（可带箭头），登记线段包围盒。"""
    x1, y1 = p1
    x2, y2 = p2
    draw.line([x1, y1, x2, y2], fill=color, width=width)
    if head:
        ang = math.atan2(y2 - y1, x2 - x1)
        size = 12
        draw.polygon([(x2, y2),
                      (x2 - size * math.cos(ang - 0.4), y2 - size * math.sin(ang - 0.4)),
                      (x2 - size * math.cos(ang + 0.4), y2 - size * math.sin(ang + 0.4))],
                     fill=color)
    SEGS.append((min(x1, x2) - 2, min(y1, y2) - 2,
                 max(x1, x2) + 2, max(y1, y2) + 2, "线"))


def chain(draw, points, color="#333333", width=3, head=True):
    """折线：逐段绘制，只在最后一段加箭头。"""
    for i in range(len(points) - 1):
        line(draw, points[i], points[i + 1], color, width,
             head and i == len(points) - 2)


# ---------------------------------------------------------------- 版面坐标
CX = 470          # 主流程中心线（方框宽 660，即 x 从 140 到 800）
KX = 1090         # 密钥扩展列中心线（方框宽 340，即 x 从 920 到 1260）

img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)

# ---------------------------------------------------------------- 标题
label(d, W / 2, 46, "DES 加密算法流程图（对应 des.c 的实现）", F_TITLE, "mm", "#1F3A5F")

# ---------------------------------------------------------------- 主流程
terminal(d, CX, 105, 200, 56, "开始", "开始")
process(d, CX, 185, 660, "输入明文（按 8 字节分组，末组用 PKCS#7 填充）", "输入明文")
process(d, CX, 255, 660, "输入 64 位密钥 K", "输入密钥")
process(d, CX, 340, 660, "初始置换 IP（64 位 → 64 位）", "IP 置换")
process(d, CX, 410, 660, "分组：L(0) = 左 32 位，R(0) = 右 32 位", "L0/R0")
process(d, CX, 560, 660,
        "第 i 轮迭代（i = 1, 2, …, 16）\n"
        "L(i) = R(i-1)\n"
        "R(i) = L(i-1) ⊕ F(R(i-1), K(i))\n"
        "F 函数：E 扩展 → 与 K(i) 异或 → S 盒代换 → P 置换",
        "第 i 轮迭代", min_h=170)
process(d, CX, 700, 660, "交换左右两半：R(16) ‖ L(16)", "左右交换")
process(d, CX, 770, 660, "逆初始置换 IP-1（64 位 → 64 位）", "IP 逆置换")
process(d, CX, 840, 660, "输出 64 位密文 C", "输出密文")
terminal(d, CX, 910, 200, 56, "结束", "结束")

# ---------------------------------------------------------------- 密钥扩展列
# 标题放在“输入密钥 K → PC-1”那条引线的上方，避免被竖线穿过
label(d, KX, 222, "密钥扩展（子密钥生成）", F_SMALL, "mm", KEY_LINE)
process(d, KX, 355, 340, "PC-1 置换（64 位 → 56 位）", "PC-1",
        fill=KEY_FILL, line=KEY_LINE, min_h=64)
process(d, KX, 440, 340, "分为 C(0)、D(0)（各 28 位）", "C0/D0",
        fill=KEY_FILL, line=KEY_LINE, min_h=64)
process(d, KX, 525, 340, "第 i 轮循环左移 LS(i)\n得到 C(i)、D(i)", "循环左移",
        fill=KEY_FILL, line=KEY_LINE, min_h=64)
process(d, KX, 610, 340, "PC-2 置换（56 位 → 48 位）", "PC-2",
        fill=KEY_FILL, line=KEY_LINE, min_h=64)
process(d, KX, 695, 340, "得到子密钥 K(i)（48 位）", "子密钥",
        fill=KEY_FILL, line=KEY_LINE, min_h=64)

# ---------------------------------------------------------------- 说明
process(d, 700, 985, 1120,
        "注：主流程与轮函数 F 分别对应 des.c 中的 des_block() 与 f_function()，子密钥由 key_schedule() 生成，\n"
        "分组与填充由 ecb_encrypt() 完成；解密使用完全相同的流程，只是子密钥按 K(16)…K(1) 逆序使用。",
        "说明", fnt=F_NOTE, fill=NOTE_FILL, line=NOTE_LINE, min_h=78)

# ---------------------------------------------------------------- 主流程连线
chain(d, [(CX, 133), (CX, 158)])
chain(d, [(CX, 212), (CX, 228)])
chain(d, [(CX, 282), (CX, 313)])
chain(d, [(CX, 367), (CX, 383)])
chain(d, [(CX, 437), (CX, 475)])
chain(d, [(CX, 645), (CX, 673)])
chain(d, [(CX, 727), (CX, 743)])
chain(d, [(CX, 797), (CX, 813)])
chain(d, [(CX, 867), (CX, 882)])

# ---------------------------------------------------------------- 密钥扩展连线
chain(d, [(800, 255), (KX, 255), (KX, 323)], KEY_LINE)      # 输入密钥 K → PC-1
chain(d, [(KX, 387), (KX, 408)], KEY_LINE)                  # PC-1 → C0/D0
chain(d, [(KX, 472), (KX, 493)], KEY_LINE)                  # C0/D0 → 循环左移
chain(d, [(KX, 557), (KX, 578)], KEY_LINE)                  # 循环左移 → PC-2
chain(d, [(KX, 642), (KX, 663)], KEY_LINE)                  # PC-2 → 子密钥 K(i)
chain(d, [(920, 695), (860, 695), (860, 560), (800, 560)], KEY_LINE)   # K(i) → 轮函数

# ---------------------------------------------------------------- 框外标注
label(d, 128, 560, "16 轮", F_SMALL, "rm", PROC_LINE)       # 放在迭代框左侧，避开方框
label(d, 830, 546, "K(i)", F_SMALL, "mm", KEY_LINE)         # 放在引线上方，避开连线


# ---------------------------------------------------------------- 版面检查
def hit(a, b, tol=1.0):
    return not (a[2] <= b[0] + tol or b[2] <= a[0] + tol or
                a[3] <= b[1] + tol or b[3] <= a[1] + tol)


for i in range(len(BOXES)):
    for j in range(i + 1, len(BOXES)):
        if hit(BOXES[i], BOXES[j]):
            PROBLEMS.append("方框重叠：%s <-> %s" % (BOXES[i][4], BOXES[j][4]))
for t in TEXTS:
    for b in BOXES:
        if hit(t, b):
            PROBLEMS.append("文字压住方框：%s <-> %s" % (t[4], b[4]))
    for s in SEGS:
        if hit(t, s):
            PROBLEMS.append("文字压住连线：%s" % t[4])
for i in range(len(TEXTS)):
    for j in range(i + 1, len(TEXTS)):
        if hit(TEXTS[i], TEXTS[j]):
            PROBLEMS.append("文字互相重叠：%s <-> %s" % (TEXTS[i][4], TEXTS[j][4]))
for t in TEXTS + BOXES:
    if t[0] < 0 or t[1] < 0 or t[2] > W or t[3] > H:
        PROBLEMS.append("超出画布：%s" % t[4])

# ---------------------------------------------------------------- 保存
out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
os.makedirs(out_dir, exist_ok=True)
out = os.path.join(out_dir, "图1 DES加密算法流程图.png")
img.save(out, "PNG")

print("saved:", out, img.size)
if PROBLEMS:
    print("LAYOUT_PROBLEM(%d):" % len(PROBLEMS))
    for p in PROBLEMS:
        print("  -", p)
else:
    print("NO_OVERLAP: 方框 %d 个、框外文字 %d 处、连线 %d 段，均未重叠"
          % (len(BOXES), len(TEXTS), len(SEGS)))