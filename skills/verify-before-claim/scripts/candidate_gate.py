#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""candidate_gate.py — 判据入库门 + 固定保留集回归（自适配三层机制的层 2 / 层 3）

为什么要有这道门
----------------
判据库会增长，但**增长本身会稀释质量**：一条没有实证来源、或反例根本跑不出 FAIL 的
判据，看起来和真判据一模一样——它排在库里、被计数、被引用，却在关键时刻**恒真**。
持续学习文献把这种失效叫「反馈投毒 / 审查者橡皮图章」：只要入库没有门，
库就会渐进劣化，且**很难被发现**（每一条新的假判据都长得像真的）。

本技能的解法很直接：**把本技能自己的核心方法，做成它自己的入库门**——
候选判据的反例**必须实际跑一次并报出 FAIL**，跑不出来就不入库。

三条硬规则（不可绕过）
----------------------
1. **编号接末尾，不重排** —— 编号是稳定标识符，外部笔记按编号引用单条判据。
2. **反例必须实跑出 FAIL 信号** —— 静态看着像反例不算；`verify` 真跑。
3. **来源必须留档** —— 来源事件 / 来源日期 / 原始输出，缺一不入库（拒绝推测型判据）。
   ⚠️ 不接受「我觉得应该会有这种情况」——那不是判据，是猜想。

用法
----
  # 生成候选骨架
  python3 scripts/candidate_gate.py new --code L42 --title "标题" --lib 本机 --out cand.md

  # 静态检查（不执行命令）：三段齐备 / 反例非占位 / 编号不冲突 / 来源齐备
  python3 scripts/candidate_gate.py check cand.md

  # 入库门：实际执行反例命令，确认它真的报 FAIL
  python3 scripts/candidate_gate.py verify cand.md

  # 层 3：固定保留集回归（既有判据库 + 各脚本自检全部重跑）
  python3 scripts/candidate_gate.py regress

  # 入库（默认 dry-run；--apply 才真写，且内部先跑 verify）
  python3 scripts/candidate_gate.py admit cand.md            # 只打印将要做什么
  python3 scripts/candidate_gate.py admit cand.md --apply

  python3 scripts/candidate_gate.py --self-test               # 阴性对照

⚠️ **为什么默认执行候选里的命令**
--------------------------------
`verify` 默认**会执行**候选文件里的 `反例命令`——不执行就没有入库门，整层机制落空。
这与 `evidence_pack.py replay` 默认**不**执行并不矛盾：**证据包的 cmd 是第三方的被审材料，
候选判据的命令是使用者本人写的自有代码**。执行前命令会打到 stderr，来源与内容可见；
`--no-exec` 可只看静态检查，但那时结论是**「未验证」，不判通过**。
⚠️ 若候选来自第三方，先审 `反例命令 / 反例准备` 两段再跑——它们是可执行文本。

⚠️ **半自动，不是全自动**
--------------------------
`admit --apply` 需要人显式敲出来——这是**人工过闸**那一环，不是技术限制。
文献对「全自动改写判据库」的警告很明确：对抗性输入会持续触发特定方向的改写，
渐进劣化且难被发现。所以：脚本负责**把门守住**，人负责**决定要不要过**。

退出码: 0 = 通过   1 = 被门拦下（或自检失败）   2 = 用法/环境错误
"""
import argparse
import datetime as _dt
import os
import re
import shutil
import subprocess
import sys
import tempfile

SECTIONS = ("现象", "判据", "反例")
SOURCE_KEYS = ("来源事件", "来源日期")
LIBS = {
    "本机": "判据库-本机与工具链.md",
    "local": "判据库-本机与工具链.md",
    "远端": "判据库-远端与接口.md",
    "remote": "判据库-远端与接口.md",
}
MIN_EXAMPLE_LEN = 18  # 与 assert_hits.py 同口径
ENTRY_RE = re.compile(r"^###\s+([LR]\d+)\s+(.+)$", re.M)
TITLE_COUNT_RE = re.compile(r"（(\d+)\s*条）")
DEFAULT_TIMEOUT = 20

TEMPLATE = """---
候选编号: {code}
目标库: {lib}
类别: {cls}
来源事件: ⟨哪天、在哪、被什么骗了一次：一句话⟩
来源日期: {today}
原始输出: ⟨那次真实输出的关键行；没有就别写这条判据⟩
---

# 候选判据 {code} · {title}

### {code} {title}

- **现象**：⟨什么情况下会看到什么。写具体的表观，不写成因⟩
- **判据**：⟨怎么验。必须能落回一条命令，或一句可机械判定的期望⟩
- **反例**：⟨一段≥18 字的实跑描述：构造什么输入、命令输出什么、为什么那就是 FAIL 信号⟩
- **反例准备**：`⟨可选：先在临时目录造数据的命令，如 printf 'alpha\\n' > sample.txt⟩`
- **反例命令**：`⟨在临时目录里执行；必须能跑出 FAIL 信号⟩`
- **反例判据**：`⟨默认 nonzero；也可写 rc:N 或 nomatch:正则⟩`

## 入库前自检

- [ ] 反例**实跑过**，且确实报了 FAIL（`verify` 通过）
- [ ] 来源事件是**真实发生过的**（日期 + 命令 + 原始输出），不是推测
- [ ] 编号接在目标库末尾，与既有编号不冲突
"""


# ── 解析 ──────────────────────────────────────────────────
def parse(path):
    """解析候选文件，返回 dict。结构性问题记入 errors（不抛异常）。"""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    cand = {"path": path, "text": text, "errors": []}

    fm = re.match(r"^---\s*\n(.*?)\n---", text, re.S)
    cand["meta"] = {}
    if fm:
        for line in fm.group(1).splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                cand["meta"][k.strip()] = v.strip()
    else:
        cand["errors"].append("缺 frontmatter（候选编号 / 目标库 / 来源事件 / 来源日期）")

    m = ENTRY_RE.search(text)
    if not m:
        cand["errors"].append("未找到条目标题（须写成 `### L42 标题`）")
        return cand
    cand["code"], cand["title"] = m.group(1), m.group(2).strip()
    cand["body"] = text[m.start():]
    for sec in SECTIONS:
        mm = re.search(r"\*\*%s\*\*[：:]\s*(.+)" % sec, cand["body"])
        cand[sec] = mm.group(1).strip() if mm else ""
        if not mm:
            cand["errors"].append("条目 %s 缺「%s」段" % (cand["code"], sec))
    cand["setup"] = _field(cand["body"], "反例准备")
    cand["cmd"] = _field(cand["body"], "反例命令")
    cand["rule"] = _field(cand["body"], "反例判据") or "nonzero"
    if not cand["cmd"]:
        cand["errors"].append(
            "缺「反例命令」—— 没有可执行命令就无法机械验证，"
            "按第 3 条硬规则不入库"
        )
    lib = cand["meta"].get("目标库", "")
    cand["lib_file"] = LIBS.get(lib, lib if lib.endswith(".md") else "")
    return cand


def _field(body, name):
    m = re.search(r"\*\*%s\*\*[：:]\s*`(.+?)`" % name, body)
    return m.group(1).strip() if m else ""


# ── 静态检查（层 2 上半：不执行命令）────────────────────────
def check(cand, skill_dir):
    """返回 (errors, warns)。errors 非空 ⇒ 不许入库。"""
    errs = list(cand["errors"])
    warns = []

    ex = cand.get("反例", "")
    if ex and len(ex) < MIN_EXAMPLE_LEN:
        errs.append("反例过短（%d 字 < %d），疑为占位：%r"
                    % (len(ex), MIN_EXAMPLE_LEN, ex))

    for k in SOURCE_KEYS:
        v = cand["meta"].get(k, "")
        if not v or v.startswith("⟨"):
            errs.append("来源留档缺「%s」—— 拒绝推测型判据入库" % k)
    raw = cand["meta"].get("原始输出", "")
    if not raw or raw.startswith("⟨"):
        warns.append("未附原始输出（建议补上那次真实输出的关键行）")

    lib_file = cand.get("lib_file")
    if not lib_file:
        errs.append("frontmatter 的「目标库」应为「本机」或「远端」")
    else:
        lib_path = os.path.join(skill_dir, "references", lib_file)
        if not os.path.isfile(lib_path):
            errs.append("目标库不存在: references/%s" % lib_file)
        else:
            with open(lib_path, encoding="utf-8") as f:
                lib_text = f.read()
            codes = ENTRY_RE.findall(lib_text)
            exist = {c for c, _t in codes}
            if cand.get("code") in exist:
                errs.append("编号 %s 已存在于 %s —— 编号是稳定标识符，"
                            "一律接末尾，禁止重排" % (cand["code"], lib_file))
            prefix = cand["code"][0]
            nums = sorted(int(c[1:]) for c in exist if c[0] == prefix)
            if nums and int(cand["code"][1:]) <= max(nums):
                warns.append("编号 %s 未接在末尾（当前最大 %s%d）—— 请确认是否有意"
                             % (cand["code"], prefix, max(nums)))
    return errs, warns


# ── 入库门：实跑反例 ──────────────────────────────────────
def evaluate(setup, cmd, rule, timeout=DEFAULT_TIMEOUT, skill_dir=""):
    """在临时目录里跑 setup + cmd，按 rule 判定是否出现 FAIL 信号。

    返回 (ok, 说明)。ok=True 表示「反例确实报出了 FAIL 信号」。

    ⚠️ **命令跑不起来不算 FAIL 信号**（rc=127 / 找不到命令 / 超时）——
    那是**探测手段自己失败**了，与「反例如期报错」同形却完全不同（第 6 类形态）。
    把它当成通过，等于让一条占位反例蒙混入库。
    """
    tmp = tempfile.mkdtemp(prefix="vbc-gate-")
    try:
        def subst(s):
            return s.replace("{tmp}", tmp).replace("{skill}", skill_dir or "")
        if setup:
            # ⚠️ 准备步骤的返回码**必须检查**：准备失败 ⇒ 反例跑的根本不是它要跑的用例，
            #    而「命令因文件不存在而崩溃」的 rc 恰好也是非零 ⇒ 会被 `nonzero` 判成
            #    「如期报 FAIL」（**假通过**）。这是 B 轮审计 B3 同族的缺口：
            #    门只验「报没报 FAIL」，不验「这个 FAIL 是否来自被判定的性质」。
            sp = subprocess.run(subst(setup), shell=True, cwd=tmp,
                                capture_output=True, text=True, timeout=timeout)
            if sp.returncode != 0:
                return False, ("反例**准备步骤失败**（rc=%d）⇒ 整个反例不可信，"
                               "不据它判定｜输出: %s"
                               % (sp.returncode,
                                  ((sp.stdout or "") + (sp.stderr or "")).strip()
                                  .replace("\n", " ⏎ ")[:160] or "（空）"))
        real = subst(cmd)
        try:
            p = subprocess.run(real, shell=True, cwd=tmp, capture_output=True,
                               text=True, timeout=timeout)
            rc, out = p.returncode, (p.stdout or "") + (p.stderr or "")
        except subprocess.TimeoutExpired:
            rc, out = 124, "TIMEOUT"
        except Exception as exc:
            rc, out = 127, "UNRUNNABLE: %s" % type(exc).__name__

        head = out.strip()[:160].replace("\n", " ⏎ ")
        if rc == 124:
            return False, "命令超时 ⇒ 未产生 FAIL 信号（探测手段自身失败）"
        if rc == 127 or "command not found" in out or "UNRUNNABLE" in out:
            return False, ("命令没跑起来（rc=127）⇒ **不是** FAIL 信号："
                           "反例命令本身无效，无法据此判定判据有效｜输出: %s"
                           % (head or "（空）"))
        if rule.startswith("rc:"):
            want = int(rule.split(":", 1)[1])
            ok = (rc == want)
            return ok, "rc=%d（期望 %d）｜输出: %s" % (rc, want, head or "（空）")
        if rule.startswith("nomatch:"):
            pat = rule.split(":", 1)[1]
            # ⚠️ 空输出不能算「未匹配」：`true` + `nomatch:永不存在` 会蒙混过门 ——
            #    什么都没跑、什么都没输出，恰好"没匹配上"。空输出 ⇒ 未产生 FAIL 信号。
            if not out.strip():
                return False, ("输出为空 ⇒ **不算** FAIL 信号：命令没产出任何东西，"
                               "无法证明检查器真的跑过（空输出 + nomatch 是常见蒙混手法）")
            ok = not re.search(pat, out)
            return ok, "输出%s匹配 %r（期望**不**匹配）｜输出: %s" % (
                "已" if re.search(pat, out) else "未", pat, head or "（空）")
        ok = (rc != 0)
        return ok, "rc=%d（期望非零）｜输出: %s" % (rc, head or "（空）")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def verify(cand, skill_dir, quiet=False, execute=True):
    """静态检查 + 实跑反例。返回 (ok, 行列表)。

    ⚠️ `execute=False`（`--no-exec`）时**不判通过**：只做静态检查，结论是「未验证」。
    理由：反例没实跑就等于没做入库门，此时放行等于把没验证过的东西当验证过——
    正是本技能要防的形态。
    """
    lines = []
    errs, warns = check(cand, skill_dir)
    for w in warns:
        lines.append("  ~ %s" % w)
    if errs:
        for e in errs:
            lines.append("  ✗ %s" % e)
        if not quiet:
            print("── 入库门 · 候选 %s ──" % cand.get("code", "?"))
            for ln in lines:
                print(ln)
            print("FAIL  静态检查未过（%d 项）—— 不入库" % len(errs))
        return False, lines

    if not execute:
        lines.append("  ~ 未执行反例命令（`--no-exec`）⇒ **未做入库门验证**，"
                     "结论为「未验证」，不得据此入库")
        if not quiet:
            print(lines[-1])
            print("REVIEW  静态检查已过，但反例未实跑 —— 补跑 `verify`（不加 --no-exec）才可入库")
        return False, lines

    # 执行前先把命令打到 stderr：候选里的命令来自**被审材料**（第三方候选尤甚），
    # 执行什么必须可见，不能闷头跑。
    if not quiet:
        sys.stderr.write("· 准备执行（候选自述命令，非本工具生成）:\n")
        if cand.get("setup"):
            sys.stderr.write("    准备: %s\n" % cand["setup"])
        sys.stderr.write("    反例: %s\n" % cand.get("cmd", ""))

    ok, detail = evaluate(cand.get("setup", ""), cand.get("cmd", ""),
                          cand.get("rule", "nonzero"), skill_dir=skill_dir)
    if not quiet:
        print("── 入库门 · 候选 %s ──" % cand.get("code", "?"))
        for ln in lines:
            print(ln)
    if ok:
        lines.append("  ✓ 反例实跑报出 FAIL 信号: %s" % detail)
        if not quiet:
            print(lines[-1])
            print("PASS  通过入库门（可 `admit --apply`；仍建议人工过闸）")
        return True, lines
    lines.append("  ✗ 反例没跑出 FAIL 信号 ⇒ 不入库: %s" % detail)
    if not quiet:
        print(lines[-1])
        print("FAIL  反例未实测出 FAIL —— 按第 2 条硬规则不入库。"
              "要么修反例，要么承认这条判据目前无法被机械验证")
    return False, lines


# ── 层 3：固定保留集回归 ──────────────────────────────────
REGRESSION = (
    ("判据库断言", "scripts/assert_hits.py"),
    ("判据库自检阴性对照", "scripts/assert_hits.py --self-test"),
    ("证据包自检", "scripts/evidence_pack.py --self-test"),
    ("环境指纹自检", "scripts/env_fingerprint.py --self-test"),
)


def regress(skill_dir):
    """既有判据的保留集必须全绿，才允许新判据入库（文献：灾难性遗忘的闸门）。"""
    print("── 固定保留集回归 ──")
    print("目录: %s" % skill_dir)
    bad = []
    for label, rel in REGRESSION:
        parts = rel.split()
        script = os.path.join(skill_dir, parts[0])
        if not os.path.isfile(script):
            print("  ✗ %s: 缺脚本 %s" % (label, parts[0]))
            bad.append(label)
            continue
        p = subprocess.run([sys.executable, script] + parts[1:],
                           capture_output=True, text=True, timeout=180)
        tail = [l for l in (p.stdout or "").splitlines() if l.strip()]
        last = tail[-1].strip() if tail else "（无输出）"
        if p.returncode == 0:
            print("  ✓ %s: %s" % (label, last))
        else:
            print("  ✗ %s: rc=%d  %s" % (label, p.returncode, last))
            bad.append(label)
    # ④ 已入库判据的**反例重跑**（信息级）：反例会随环境漂移而失效 ——
    #    L40 就出现过「换一类 grep 后旧反例静默 PASS」。这里不参与 rc（因为
    #    「前提在本机不成立 ⇒ 反例给 rc=3」是**诚实的未验证**，不该阻断），
    #    但必须让它**可见**：静默失效比报错更贵。
    items = _entries_with_cmd(skill_dir)
    print("── 已入库判据的反例重跑（信息级，不参与退出码）──")
    if not items:
        print("  - 无可机械复跑的反例（存量条目只写了描述性反例，属已知缺口）")
    for code, setup, cmd, rule in items:
        ok_r, detail = evaluate(setup, cmd, rule, skill_dir=skill_dir)
        print("  %s %s: %s" % ("✓ 报 FAIL" if ok_r else "~ 未报 FAIL", code, detail[:90]))

    if bad:
        print("FAIL  保留集 %d 项不通过 ⇒ 本轮**禁止**入库（先修回归）" % len(bad))
        return 1
    print("PASS  保留集全绿（%d 项）—— 允许入库" % len(REGRESSION))
    return 0


def _entries_with_cmd(skill_dir):
    """扫出带「反例命令」字段的已入库条目：(编号, 准备, 命令, 判据)。"""
    out = []
    for fname in ("判据库-本机与工具链.md", "判据库-远端与接口.md"):
        path = os.path.join(skill_dir, "references", fname)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as f:
            text = f.read()
        marks = list(re.finditer(r"^###\s+([LR]\d+)[^\n]*$", text, re.M))
        for i, m in enumerate(marks):
            end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
            body = text[m.start():end]
            cmd = _field(body, "反例命令")
            if cmd:
                out.append((m.group(1), _field(body, "反例准备"), cmd,
                            _field(body, "反例判据") or "nonzero"))
    return out


# ── 入库（半自动：默认 dry-run）────────────────────────────
def entry_text(cand):
    """生成要追加的条目文本（保留三段 + 可复跑的反例命令 + 来源）。"""
    out = ["### %s %s" % (cand["code"], cand["title"]),
           "- **现象**：%s" % cand["现象"],
           "- **判据**：%s" % cand["判据"],
           "- **反例**：%s" % cand["反例"]]
    if cand.get("cmd"):
        # ⚠️ 「反例准备」必须是**独立字段行**。早先把它并进「反例命令」行的括号里，
        #    结果 `_field(body, "反例准备")` 永远读不到 ⇒ 后续所有机械复跑都在
        #    **空准备**下运行 ⇒ 反例因"文件不存在"而崩溃，而崩溃的 rc 恰好非零，
        #    又被 `nonzero` 判成「如期报 FAIL」（假通过）。字段结构就是接口，不能省。
        if cand.get("setup"):
            out.append("- **反例准备**：`%s`" % cand["setup"])
        out.append("- **反例命令**：`%s`" % cand["cmd"])
        out.append("- **反例判据**：`%s`" % cand.get("rule", "nonzero"))
    if cand["meta"].get("来源事件"):
        out.append("- **来源**：%s" % cand["meta"]["来源事件"])
    return "\n".join(out) + "\n"


def admit(cand, skill_dir, apply=False, section=None):
    ok, _ = verify(cand, skill_dir, quiet=False)
    if not ok:
        print("→ 未过入库门，拒绝入库")
        return 1

    lib_file = cand["lib_file"]
    lib_path = os.path.join(skill_dir, "references", lib_file)
    with open(lib_path, encoding="utf-8") as f:
        lib_text = f.read()

    cls = (cand["meta"].get("类别") or "").strip()
    target = m = None
    if section:  # 显式指定插到哪一节（节标题关键字）
        m = re.search(r"^##\s+[^\n]*%s[^\n]*$" % re.escape(section), lib_text, re.M)
        if not m:
            print("✗ 目标库里没有匹配 %r 的节" % section)
            return 1
    elif cls:
        # 优先插进「类 N 续」那一节（新增判据向来归到续节），没有再退回「类 N」正节
        m = _pick_section(lib_text, cls, cand["code"])
        if m is None:
            print("✗ 未能唯一确定「类 %s」的目标节 ⇒ 请用 `--section <节标题关键字>` 显式指定"
                  "（同名前缀的续节可能有多个，本工具**不做猜测**）" % cls)
            return 1
    if m:
        # ⚠️ 插到**节尾**（不是节标题之后）：插在标题后会落在**节前言之前** ——
        #    既把前言架空，又让连续入库的顺序反转（实测出现 L40 排在 L38/L39 之前）。
        #    节尾 = 有条目时接在最后一条之后（编号单调），无条目时落在前言之后（前言不被架空）。
        rest = lib_text[m.end():]
        nxt = re.search(r"^##\s+", rest, re.M)
        target = m.end() + (nxt.start() if nxt else len(rest))
        lib_text = _widen_range(lib_text, m.group(0), cand["code"])

    block = entry_text(cand)
    new_text = _insert(lib_text, target, block)
    m = TITLE_COUNT_RE.search(new_text)
    if m:
        new_text = (new_text[:m.start()]
                    + "（%d 条）" % (int(m.group(1)) + 1)
                    + new_text[m.end():])
    else:
        print("✗ 目标库标题没有「（N 条）」，无法更新计数 —— 不入库")
        return 1

    print("── 将要写入 references/%s ──" % lib_file)
    print(block)
    if not apply:
        print("（dry-run：未写入。加 --apply 才真写 —— 这一下是**人工过闸**）")
        return 0
    with open(lib_path, "w", encoding="utf-8") as f:
        f.write(new_text)
    print("已写入。请复跑 `python3 scripts/assert_hits.py` 确认计数与覆盖仍齐备。")
    return 0


def _range_of(heading, prefix):
    """解析节标题括号里的编号范围，返回编号集合（无编号 ⇒ None）。

    支持三种写法：`（L31）` / `（L38–L40）` / `（L35–L37、L41）` / `（远端侧，R33–R35）`。
    """
    m = re.search(r"（[^）]*）", heading)
    if not m:
        return None
    inner = m.group(0)
    out = set()
    for a, b in re.findall(r"%s(\d+)\s*[–-]\s*%s(\d+)" % (prefix, prefix), inner):
        out.update(range(int(a), int(b) + 1))
    # 去掉范围后剩下的单编号
    for x in re.findall(r"%s(\d+)" % prefix,
                        re.sub(r"%s\d+\s*[–-]\s*%s\d+" % (prefix, prefix), " ", inner)):
        out.add(int(x))
    return out or None


def _pick_section(lib_text, cls, code):
    """按类别挑目标节。返回匹配对象；**歧义就不猜**（返回 None）。

    ⚠️ 「类 N 续」可能不止一个（如「类 3 续 · 只读模式…（L31）」与
    「类 3 续 · 通道相关…（L35–L37、L41）」）。`re.search` 只取第一个 ⇒
    新条目会被**静默塞进错的节**，且 `admit` 仍 rc=0、`assert_hits` 仍 PASS。
    消歧办法：**用节标题里的编号范围判定归属** —— 编号在范围内才是它；
    多个候选都无范围或不含该编号 ⇒ 不猜，请调用方用 `--section` 指定。
    """
    for pat in (r"^##\s+类\s*%s[^\n]*续[^\n]*$" % re.escape(cls),
                r"^##\s+类\s*%s[^\n]*$" % re.escape(cls)):
        cands = list(re.finditer(pat, lib_text, re.M))
        if not cands:
            continue
        if len(cands) == 1:
            return cands[0]
        prefix, num = code[0], int(code[1:])
        for mm in cands:
            rng = _range_of(mm.group(0), prefix)
            if rng and num in rng:
                return mm
        print("  · 命中 %d 个同名前缀的「类 %s」节，编号 %s 都不在其范围内："
              % (len(cands), cls, code))
        for mm in cands:
            print("      %s" % mm.group(0).strip())
        return None
    return None


def _widen_range(lib_text, heading, code):
    """把节标题里的编号范围推到新编号。

    两种情形分开处理，避免把**不连续的编号集合**写成连续范围：
      · 单段且紧邻（`（L38–L40）` + L41）⇒ 扩展上界 → `（L38–L41）`
      · 多段或不紧邻（`（L35–L37、L41）` + L42）⇒ 追加 → `（L35–L37、L41、L42）`
    标题里的范围是**索引**：不更新就与实际条目不符 —— 而索引失配正是
    判据编号被当作稳定标识符时最该避免的漂移。
    """
    p, n = code[0], int(code[1:])
    m = re.search(r"（[^）]*）", heading)
    if not m:
        return lib_text
    inner = m.group(0)
    nums = _range_of(heading, p)
    if not nums or n in nums or n <= max(nums):
        return lib_text
    ranges = list(re.finditer(r"%s(\d+)\s*[–-]\s*%s(\d+)" % (p, p), inner))
    singles = [int(x) for x in re.findall(
        r"%s(\d+)" % p,
        re.sub(r"%s\d+\s*[–-]\s*%s\d+" % (p, p), " ", inner))]
    if len(ranges) == 1 and not singles and n == int(ranges[0].group(2)) + 1:
        new_inner = inner[:ranges[0].start(2)] + str(n) + inner[ranges[0].end(2):]
    else:
        new_inner = inner[:-1] + "、%s%d）" % (p, n)
    return lib_text.replace(heading, heading.replace(inner, new_inner, 1), 1)


def _insert(text, pos, block):
    if pos is None:
        return text.rstrip("\n") + "\n\n" + block
    head = text[:pos].rstrip("\n")
    tail = text[pos:].lstrip("\n")
    return head + "\n\n" + block + "\n" + tail


# ── 自检 ──────────────────────────────────────────────────
def _write(tmp, name, body):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(body)
    return p


def _cand(code="L90", cls="7", lib="本机", 现象="x" * 30, 判据="y" * 30,
         反例="z" * 30, cmd="", setup="", rule="nonzero",
         event="2026-10-01 实测：…", date="2026-10-01", raw="rc=1 空输出",
         drop=()):
    parts = ["---",
             "候选编号: %s" % code,
             "目标库: %s" % lib,
             "类别: %s" % cls]
    if "来源事件" not in drop:
        parts.append("来源事件: %s" % event)
    if "来源日期" not in drop:
        parts.append("来源日期: %s" % date)
    if "原始输出" not in drop:
        parts.append("原始输出: %s" % raw)
    parts.append("---")
    if "frontmatter" in drop:
        parts = []
    body = ["### %s 标题" % code]
    if "现象" not in drop:
        body.append("- **现象**：%s" % 现象)
    if "判据" not in drop:
        body.append("- **判据**：%s" % 判据)
    if "反例" not in drop:
        body.append("- **反例**：%s" % 反例)
    if setup:
        body.append("- **反例准备**：`%s`" % setup)
    if cmd:
        body.append("- **反例命令**：`%s`" % cmd)
    if rule and cmd:
        body.append("- **反例判据**：`%s`" % rule)
    return "\n".join(parts) + "\n\n" + "\n".join(body) + "\n"


def self_test(skill_dir):
    """阴性对照：缺陷候选必须被门拦下，合格候选必须放行。"""
    print("── 阴性对照 (--self-test) ──")
    tmp = tempfile.mkdtemp(prefix="vbc-gate-st-")
    fails = []
    try:
        # 合格候选（反例真能跑出 FAIL）
        good = _write(tmp, "good.md", _cand(
            cmd='grep -c "ZZZ_NOT_THERE" sample.txt',
            setup="printf 'alpha\\nbeta\\n' > sample.txt"))
        ok, lines = verify(parse(good), skill_dir, quiet=True)
        if ok:
            print("  ✓ 合格候选通过入库门（反例实跑 rc≠0）")
        else:
            fails.append("合格候选被拒（门过严）: %s" % lines[-1])

        # nomatch 型合格候选
        # 输出为 "0"（没命中）；期望「输出里不出现 ^1$」⇒ 未匹配 ⇒ 判 FAIL 信号
        good2 = _write(tmp, "good2.md", _cand(
            code="L91", cmd='printf "hello\\n" | grep -c "ZQX"',
            rule="nomatch:^1$"))
        ok2, lines2 = verify(parse(good2), skill_dir, quiet=True)
        if ok2:
            print("  ✓ nomatch 型合格候选通过（输出未匹配预期串）")
        else:
            fails.append("nomatch 型合格候选被拒: %s" % lines2[-1])

        cases = [
            ("反例恒 PASS（rc=0）", _cand(code="L92", cmd="echo ok"),
             "FAIL 信号"),
            ("反例占位（不足 18 字）", _cand(code="L93", 反例="待补。",
                                        cmd="false"), "占位"),
            ("编号与既有判据冲突", _cand(code="L01", cmd="false"), "重排"),
            ("缺「判据」段", _cand(code="L94", cmd="false", drop=("判据",)),
             "判据"),
            ("缺来源留档", _cand(code="L95", cmd="false",
                            drop=("来源事件", "来源日期")), "来源"),
            ("缺「反例命令」", _cand(code="L96"), "反例命令"),
            ("缺 frontmatter", _cand(code="L97", cmd="false",
                                 drop=("frontmatter",)), "frontmatter"),
            # ⚠️ 最隐蔽的一类：命令压根跑不起来（rc=127）却与「反例如期报错」同形
            ("反例命令无效（rc=127）",
             _cand(code="L98", cmd="__vbc_no_such_command__ --x"), "没跑起来"),
            # ⚠️ 空输出 + nomatch：什么都没跑，恰好"没匹配上" ⇒ 蒙混过门
            ("空输出 + nomatch 蒙混",
             _cand(code="L99", cmd="true", rule="nomatch:WILL_NEVER_APPEAR"),
             "输出为空"),
            # ⚠️ 准备步骤失败 ⇒ 反例跑的不是它要跑的用例，而崩溃的 rc 也是非零
            ("准备步骤失败（rc≠0）",
             _cand(code="L99", setup="__vbc_no_such_setup__", cmd="false"),
             "准备步骤失败"),
        ]
        for label, body, keyword in cases:
            p = _write(tmp, "bad_%s.md" % label[:2], body)
            ok_b, lines_b = verify(parse(p), skill_dir, quiet=True)
            if ok_b:
                fails.append("%s 竟通过了入库门 ⇒ 门失效" % label)
            elif any(keyword in l for l in lines_b):
                print("  ✓ %s 被拦下（%s）"
                      % (label, [l for l in lines_b if keyword in l][0].strip()[:70]))
            else:
                fails.append("%s 被拦下，但理由里没有关键词 %r: %s"
                             % (label, keyword, lines_b[-1]))

        # 插入位置（A3 S-2）：新条目必须落在**节尾**——前言之后、最后一条之后，
        # 编号单调。修前会插在节前言之前、让连续入库顺序反转。
        tmp_skill = os.path.join(tmp, "skillcopy")
        shutil.copytree(skill_dir, tmp_skill,
                        ignore=shutil.ignore_patterns(".git", "__pycache__"))
        pos_cand = parse(_write(tmp, "pos.md", _cand(code="L42", cmd="false")))
        rc_pos = admit(pos_cand, tmp_skill, apply=True, section="证据不可复跑")
        lib_path = os.path.join(tmp_skill, "references", "判据库-本机与工具链.md")
        with open(lib_path, encoding="utf-8") as f:
            lib = f.read()
        try:
            i38, i39, i40, i42 = (lib.index("### L38"), lib.index("### L39"),
                                  lib.index("### L40"), lib.index("### L42"))
            pre = lib.index("本族口径")
            if rc_pos == 0 and i38 < i39 < i40 < i42 and pre < i38:
                print("  ✓ 新条目落在节尾（前言 → L38 → L39 → L40 → L42，编号单调）")
            else:
                fails.append("新条目未落在节尾（位置 %s，前提 rc=%d）"
                             % ((i38, i39, i40, i42, pre), rc_pos))
        except ValueError as exc:
            fails.append("插入位置检查无法定位锚点: %s" % exc)

        # F-1（B 轮 P1）：`--cls` 路径遇**同名前缀的多个续节**必须拒绝，不得塞错节。
        tmp_skill2 = os.path.join(tmp, "skillcopy2")
        shutil.copytree(skill_dir, tmp_skill2,
                        ignore=shutil.ignore_patterns(".git", "__pycache__"))
        cls_cand = parse(_write(tmp, "cls.md", _cand(code="L42", cls="3", cmd="false")))
        rc_cls = admit(cls_cand, tmp_skill2, apply=True)  # 不给 --section ⇒ 走 --cls 路径
        with open(os.path.join(tmp_skill2, "references", "判据库-本机与工具链.md"),
                  encoding="utf-8") as f:
            lib2 = f.read()
        if rc_cls != 0:
            print("  ✓ --cls 路径的同名前缀歧义被拒绝（未把条目塞进错的节）")
        else:
            seg_start = lib2.find("## 类 3 续 · 只读模式")
            seg_end = lib2.find("## 类 5", seg_start)
            if seg_start >= 0 and "### L42" in lib2[seg_start:seg_end]:
                fails.append("--cls 路径把 L42 静默塞进「类 3 续 · 只读模式」节（F-1 复发）")
            else:
                fails.append("--cls 路径未拒绝歧义（rc=0，行为未定义）")

        # 条目字段结构：`反例准备` 必须是**独立字段行**（并进「反例命令」行会让
        # 后续机械复跑读不到准备 ⇒ 在空准备下跑 ⇒ 崩溃的 rc 被当成「如期报 FAIL」）
        et = entry_text(parse(_write(tmp, "et.md", _cand(
            code="L99", setup="printf x > {tmp}/y", cmd="false"))))
        if "- **反例准备**：`printf x > {tmp}/y`" in et and \
           et.count("- **反例命令**：") == 1:
            print("  ✓ 条目字段结构正确（「反例准备」独立成行）")
        else:
            fails.append("entry_text 未把「反例准备」写成独立字段行")

        # 节标题编号范围：连续则扩展上界、多段则追加（不得把不连续写成连续）
        r1 = _widen_range("H（L38–L40）", "H（L38–L40）", "L41")
        r2 = _widen_range("H（L35–L37、L41）", "H（L35–L37、L41）", "L42")
        if "L38–L41" in r1 and "L35–L37、L41、L42" in r2:
            print("  ✓ 节标题编号范围更新正确（连续扩展 / 多段追加）")
        else:
            fails.append("节标题编号范围更新有误: %r / %r" % (r1, r2))

        # 回归：保留集必须全绿
        rc = regress(skill_dir)
        if rc != 0:
            fails.append("固定保留集回归未全绿（rc=%d）" % rc)

        if fails:
            for f in fails:
                print("  ✗ %s" % f)
            print("FAIL  自检未通过（%d 项）" % len(fails))
            return 1
        print("PASS  阴性对照通过 —— 全部缺陷用例被拦下，合格候选放行，保留集全绿")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="判据入库门 + 保留集回归")
    ap.add_argument("subcmd", nargs="?", help="new / check / verify / regress / admit")
    ap.add_argument("target", nargs="*", help="候选文件路径")
    ap.add_argument("--code", help="new: 候选编号（如 L42）")
    ap.add_argument("--title", help="new: 标题")
    ap.add_argument("--lib", default="本机", help="new: 目标库（本机 / 远端）")
    ap.add_argument("--cls", default="7", help="new: 失败形态类别号")
    ap.add_argument("--out", help="new: 输出路径")
    ap.add_argument("--skill-dir", default=None, help="技能目录（默认脚本的上一级）")
    ap.add_argument("--apply", action="store_true", help="admit: 真写入（默认 dry-run）")
    ap.add_argument("--section", help="admit: 指定插到哪一节（节标题关键字）")
    ap.add_argument("--no-exec", action="store_true",
                    help="verify: 只做静态检查、不执行反例命令（结论为「未验证」，不判通过）")
    ap.add_argument("--self-test", action="store_true", help="阴性对照")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    skill_dir = os.path.abspath(args.skill_dir) if args.skill_dir \
        else os.path.dirname(here)

    if args.self_test:
        return self_test(skill_dir)

    sub = args.subcmd
    if sub == "new":
        if not (args.code and args.title and args.out):
            print("用法: new --code L42 --title \"标题\" --out cand.md "
                  "[--lib 本机|远端] [--cls 7]")
            return 2
        lib_file = LIBS.get(args.lib, args.lib)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(TEMPLATE.format(code=args.code, title=args.title,
                                    lib=args.lib, cls=args.cls,
                                    today=_dt.date.today().isoformat()))
        print("已生成候选骨架: %s（目标库 %s，编号接末尾后再 admit）" %
              (args.out, lib_file))
        return 0

    if sub == "regress":
        return regress(skill_dir)

    if sub in ("check", "verify", "admit"):
        if not args.target:
            print("用法: %s <候选文件.md>" % sub)
            return 2
        cand = parse(args.target[0])
        if sub == "check":
            errs, warns = check(cand, skill_dir)
            for w in warns:
                print("  ~ %s" % w)
            if errs:
                for e in errs:
                    print("  ✗ %s" % e)
                print("FAIL  静态检查未过（%d 项）" % len(errs))
                return 1
            print("PASS  静态检查通过（下一步: verify —— 反例必须实跑出 FAIL）")
            return 0
        if sub == "verify":
            ok = verify(cand, skill_dir, execute=not args.no_exec)[0]
            return 0 if ok else 1
        return admit(cand, skill_dir, apply=args.apply, section=args.section)

    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
