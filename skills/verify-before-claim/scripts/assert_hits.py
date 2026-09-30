#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""assert_hits.py — 判据库计数断言（本技能自检）

用途
----
把「判据库应该有多少条、覆盖哪几类、每条必须带什么」变成可执行断言，
避免手工维护时静默丢条目（少一条不会报错，只会让某类形态悄悄失去覆盖）。

检查项
------
  1. 两份判据库文件存在
  2. 条目数 == **从判据库标题「（N 条）」派生**的期望
     （⚠️ 标题是**唯一事实源**，本文件**不复述任何具体数字**——复述就是第二处口径，必然漂移）
  3. 每条同时含「现象 / 判据 / 反例」三段，且反例非占位
  4. 失败形态类别**逐份文件**核对齐备（见 CLASS_FILE_MAP）
     ⚠️ 不能只判「两份合并后的类集合」——那会被跨文件掩护（实测到的假 PASS）
  5. 两份文件的加载元数据齐备（加载条件 / 命中标签）
  6. 条目编号在各自文件内唯一且连续

用法
----
  python3 scripts/assert_hits.py                # 检查技能根目录（脚本的上一级）
  python3 scripts/assert_hits.py <技能目录>
  python3 scripts/assert_hits.py --self-test    # 阴性对照：证明本脚本能报 FAIL

⚠️ 为什么必须提供 --self-test
---------------------------
一个只报 PASS 的检查器与「一切正常」不可区分。--self-test 会构造一份
**必然不合格** 的样本副本（删掉某条的「反例」段），确认本脚本对它报 FAIL；
若连不合格样本都报 PASS，说明断言已失效，此时它对真实目录给出的 PASS 无意义。

退出码: 0 = 全部断言通过   1 = 有断言失败
"""
import argparse
import os
import re
import shutil
import sys
import tempfile

# 期望值的**单一事实源 = 判据库文件标题里的「（N 条）」**。
# 2026-09-30（v0.1.4）：原先在此硬编码 30/26，判据新增后本处忘记同步 ⇒ 自检长期 FAIL。
# 现改为运行时从标题派生：**只有标题需要维护**，本脚本不再重复声明口径。
# ⚠️ 标题缺失或格式不符 ⇒ 直接判 FAIL，**不得静默取默认值**——静默兜底正是本技能要防的假 PASS。
SPEC = ("判据库-本机与工具链.md", "判据库-远端与接口.md")
TITLE_COUNT_RE = re.compile(r"（(\d+)\s*条）")
# 每个失败形态类别**应出现在哪份判据库**里（键 = 类号，值 = 文件名集合）。
# ⚠️ 为什么不能只查「两份合并后的类集合」：并集会**跨文件互相掩护**——把本机库的整个
#    「类 7」节删掉，远端库还有同名节，合并集合仍含 7 ⇒ 覆盖检查**静默报 PASS**。
#    这正是本技能第 6 / 7 类要防的形态：**一处信号被另一处的同类信号掩盖**。
# ⚠️ 新增类别时必须同步本表；漏登记会被下方「未登记」检查抓住（不会静默放过）。
CLASS_FILE_MAP = {
    1: {"判据库-本机与工具链.md"},
    2: {"判据库-本机与工具链.md"},
    3: {"判据库-本机与工具链.md", "判据库-远端与接口.md"},
    4: {"判据库-远端与接口.md"},
    5: {"判据库-本机与工具链.md", "判据库-远端与接口.md"},
    6: {"判据库-远端与接口.md"},
    7: {"判据库-本机与工具链.md", "判据库-远端与接口.md"},
}
SECTIONS = ("现象", "判据", "反例")
REF_META_KEYS = ("加载条件", "命中标签")
ENTRY_RE = re.compile(r"^###\s+([LR]\d+)\s+(.+)$", re.M)
CLASS_RE = re.compile(r"^##\s+类\s*(\d+)", re.M)
MIN_EXAMPLE_LEN = 18


def split_entries(text):
    """把文件切成 [(编号, 标题, 正文块)]。"""
    marks = list(ENTRY_RE.finditer(text))
    out = []
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        out.append((m.group(1), m.group(2).strip(), text[m.start():end]))
    return out


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def read_frontmatter(text):
    m = re.match(r"^---\s*\n(.*?)\n---", text, re.S)
    return m.group(1) if m else ""


def derive_expected(ref_dir):
    """从各判据库**标题**派生期望条目数。

    返回 (期望字典, 失败列表)。标题缺「（N 条）」时记入失败 —— 宁可报 FAIL，
    也不静默用一个猜出来的期望值（**静默兜底 = 假 PASS 的来源**）。
    """
    exp, fails = {}, []
    for fname in SPEC:
        path = os.path.join(ref_dir, fname)
        if not os.path.isfile(path):
            continue  # 缺文件由主流程报
        m = TITLE_COUNT_RE.search(read(path))
        if m:
            exp[fname] = int(m.group(1))
        else:
            fails.append("%s 标题未写「（N 条）」，无法派生期望值" % fname)
    return exp, fails


def check(root):
    """返回 (失败列表, 信息行列表)。失败列表非空即判 FAIL。"""
    fails, info = [], []
    ref_dir = os.path.join(root, "references")

    if not os.path.isdir(ref_dir):
        return ["references/ 目录不存在"], info

    exp, exp_fails = derive_expected(ref_dir)
    fails.extend(exp_fails)

    total = 0
    per_file = {}
    for fname in SPEC:
        want = exp.get(fname)
        path = os.path.join(ref_dir, fname)
        if not os.path.isfile(path):
            fails.append("缺文件: references/%s" % fname)
            continue
        text = read(path)

        fm = read_frontmatter(text)
        for key in REF_META_KEYS:
            if key not in fm:
                fails.append("%s 加载元数据缺「%s」" % (fname, key))

        per_file[fname] = {int(num) for num in CLASS_RE.findall(text)}

        entries = split_entries(text)
        total += len(entries)
        if want is None:
            pass  # 已在 derive_expected 记入 FAIL
        elif len(entries) != want:
            fails.append("%s 条目数 %d ≠ 标题派生期望 %d" % (fname, len(entries), want))

        nums = [e[0] for e in entries]
        dup = sorted({n for n in nums if nums.count(n) > 1})
        if dup:
            fails.append("%s 编号重复: %s" % (fname, "、".join(dup)))

        # 连续性：只查重复挡不住「删掉一条 + 改标题计数」—— 那样全库静默 PASS，
        # 而按编号引用单条判据的外部笔记会**静默指向别处**（编号是稳定标识符）。
        seq = sorted(int(n[1:]) for n in nums)
        if seq != list(range(1, max(seq) + 1)):
            gap = [n for n in range(1, max(seq) + 1) if n not in seq]
            fails.append("%s 编号不连续（缺 %s）—— 编号是稳定标识符，"
                         "缺号会让按编号的引用静默失配"
                         % (fname, "、".join(str(g) for g in gap) or "未知"))

        for code, title, body in entries:
            for sec in SECTIONS:
                # 三段以 `- **现象**：` 形式出现；这里只要求出现该标记词。
                if ("**%s**" % sec) not in body:
                    fails.append("%s 条目 %s 缺「%s」段" % (fname, code, sec))
            m = re.search(r"\*\*反例\*\*[：:]\s*(.+)", body)
            if m and len(m.group(1).strip()) < MIN_EXAMPLE_LEN:
                fails.append(
                    "%s 条目 %s 的反例过短（疑为占位）: %r"
                    % (fname, code, m.group(1).strip())
                )
        info.append("%s: %d 条" % (fname, len(entries)))

    # 逐类、逐文件核对（不做合并集合的判断：那会被跨文件掩护，见 CLASS_FILE_MAP 注释）
    miss, stray = [], []
    for cls, files in sorted(CLASS_FILE_MAP.items()):
        for fname in sorted(files):
            if fname in per_file and cls not in per_file[fname]:
                miss.append("第 %d 类缺于 %s" % (cls, fname))
    for fname, got in sorted(per_file.items()):
        for cls in sorted(got - set(CLASS_FILE_MAP)):
            stray.append("%s 的「类 %d」未登记进 CLASS_FILE_MAP" % (fname, cls))
    if miss or stray:
        fails.append("失败形态覆盖不全: %s" % "、".join(miss + stray))
    else:
        info.append(
            "失败形态: 按文件逐类核对齐备（类 %d–%d）"
            % (min(CLASS_FILE_MAP), max(CLASS_FILE_MAP))
        )

    want_total = sum(exp.values())
    if total != want_total:
        fails.append("判据总数 %d ≠ 标题派生期望 %d" % (total, want_total))
    else:
        info.append("判据总数: %d 条" % total)

    return fails, info


def run(root, label):
    print("── %s ──" % label)
    print("目录: %s" % root)
    fails, info = check(root)
    for line in info:
        print("  ✓ %s" % line)
    if fails:
        for f in fails:
            print("  ✗ %s" % f)
        print("FAIL  断言未通过（%d 项）" % len(fails))
        return 1
    print("PASS  全部断言通过")
    return 0


def self_test(root, script_path):
    """阴性对照：不合格样本必须报 FAIL；合格样本必须报 PASS。

    两条都成立，才说明本检查器「能区分对错」而不是恒报 PASS。
    """
    print("── 阴性对照 (--self-test) ──")
    tmp = tempfile.mkdtemp(prefix="vbc-selftest-")
    try:
        dst = os.path.join(tmp, "skill")
        shutil.copytree(root, dst, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        target = os.path.join(dst, "references", "判据库-本机与工具链.md")
        text = read(target)
        # 删掉**第一条判据**的「反例」段 —— 本条应被断言抓住。
        # ⚠️ 必须锚定「条目里的那一行」（`- **反例**：`），不能用 str.replace 撞首处：
        # 文件顶部的用法说明里也含 `**反例**` 字样，撞上去等于没改条目。
        mutated = re.sub(r"^-\s*\*\*反例\*\*[：:].*$",
                         "- **对照**：（对照段已被移除）",
                         text, count=1, flags=re.M)
        if mutated == text:
            print("REVIEW  样本未被改动，无法做对照（请检查条目格式）")
            return 2
        with open(target, "w", encoding="utf-8") as f:
            f.write(mutated)

        fails, _info = check(dst)
        caught = any("反例" in f for f in fails)
        if caught:
            print("  ✓ 不合格样本被判 FAIL（%d 项）: %s" % (len(fails), fails[0]))
        else:
            print("  ✗ 不合格样本未被抓住 ⇒ 本检查器失效，其 PASS 不可采信")
            return 1

        fails_ok, _ = check(root)
        if fails_ok:
            print("  ✗ 合格样本被判 FAIL（%d 项）" % len(fails_ok))
            return 1
        print("  ✓ 合格样本判 PASS —— 检查器能区分对错")
        print("PASS  阴性对照通过")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="判据库计数断言（本技能自检）")
    ap.add_argument("skill_dir", nargs="?", default=None, help="技能目录（默认取脚本的上一级）")
    ap.add_argument("--self-test", action="store_true",
                    help="阴性对照：确认本脚本能对不合格样本报 FAIL")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(args.skill_dir) if args.skill_dir else os.path.dirname(here)

    if args.self_test:
        return self_test(root, os.path.abspath(__file__))
    return run(root, "判据库断言")


if __name__ == "__main__":
    sys.exit(main())
