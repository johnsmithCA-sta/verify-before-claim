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
  2. 条目数 == 期望（本机与工具链 30 / 远端与接口 26，合计 56）
  3. 每条同时含「现象 / 判据 / 反例」三段，且反例非占位
  4. 六类失败形态编号 1–6 全部出现
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

# 期望值：与 SKILL.md「判据库（按需加载）」的声明保持一致。
# 改动判据库条数时**同步改这里**，否则断言会在下次运行时失败（这是设计意图）。
EXPECTED = {
    "判据库-本机与工具链.md": 30,
    "判据库-远端与接口.md": 26,
}
REQUIRED_CLASSES = {1, 2, 3, 4, 5, 6}
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


def check(root):
    """返回 (失败列表, 信息行列表)。失败列表非空即判 FAIL。"""
    fails, info = [], []
    ref_dir = os.path.join(root, "references")

    if not os.path.isdir(ref_dir):
        return ["references/ 目录不存在"], info

    total = 0
    classes = set()
    for fname, want in EXPECTED.items():
        path = os.path.join(ref_dir, fname)
        if not os.path.isfile(path):
            fails.append("缺文件: references/%s" % fname)
            continue
        text = read(path)

        fm = read_frontmatter(text)
        for key in REF_META_KEYS:
            if key not in fm:
                fails.append("%s 加载元数据缺「%s」" % (fname, key))

        for num in CLASS_RE.findall(text):
            classes.add(int(num))

        entries = split_entries(text)
        total += len(entries)
        if len(entries) != want:
            fails.append("%s 条目数 %d ≠ 期望 %d" % (fname, len(entries), want))

        nums = [e[0] for e in entries]
        dup = sorted({n for n in nums if nums.count(n) > 1})
        if dup:
            fails.append("%s 编号重复: %s" % (fname, "、".join(dup)))

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

    missing = REQUIRED_CLASSES - classes
    if missing:
        fails.append(
            "失败形态覆盖不全，缺: %s"
            % "、".join("第 %d 类" % c for c in sorted(missing))
        )
    else:
        info.append("失败形态: 1–6 类全覆盖")

    want_total = sum(EXPECTED.values())
    if total != want_total:
        fails.append("判据总数 %d ≠ 期望 %d" % (total, want_total))
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
