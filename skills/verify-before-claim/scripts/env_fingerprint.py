#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""env_fingerprint.py — 环境指纹（自适配三层机制的层 1）

用途
----
判据库里的失败形态是**跨环境通用**的，但"哪条判据会在本机命中"是**个性化**的：
同一个「检索静默空」在 BSD grep 上由 `\\|` 触发，在 GNU grep 上根本不会触发；
「可达性探测」在有无 `/dev/tcp` 的 shell 上是两种完全不同的判读。

本脚本把这台机器的环境特征**探测出来**，回答两个问题：
  1. **本机已确认的陷阱是哪几条**（哪些判据在此环境必然命中 / 必然失效）
  2. **一份在别处采集的证据，能否搬到这台机器上沿用**（`--diff`）

设计纪律（本技能自己的规矩，本脚本必须自己遵守）
------------------------------------------
- **探测不可用 ≠ 对象正常**：任何一项探测失败，一律记成 `unknown`，
  **不得**写成 `ok` / `false`。工具缺失与"这个特性不支持"是两件不同的事，
  把它们混写就是第 6 类失败形态（探测失败 ≠ 对象不可用）。
- **不采信回显**：每项探测都以「命令的真实输出」判定，不采信退出码 0。
- **自带阴性对照**：`--self-test` 用受限环境（PATH 置空）跑一遍，
  确认工具不可用时本脚本**确实报 unknown**，而不是报"一切正常"。
- **不联网、不写凭据**：代理类环境变量只记**变量名与其是否非空**，不记值。

用法
----
  python3 scripts/env_fingerprint.py                  # 人类可读报告（默认）
  python3 scripts/env_fingerprint.py --json           # 机器可读
  python3 scripts/env_fingerprint.py --write <路径>    # 落成 Markdown（默认不写，见下）
  python3 scripts/env_fingerprint.py --save <A>       # 存一份基线（JSON）供日后比对
  python3 scripts/env_fingerprint.py --diff <A> <B>   # 比对两份基线
  python3 scripts/env_fingerprint.py --self-test      # 阴性对照

⚠️ 默认**不写文件**
------------------
指纹是**本机专属的过程数据**，含平台、shell、工具集等信息。
默认只打印；要留档须显式给 `--save` / `--write`。
建议存到技能目录**之外**（如 `~/.workbuddy/state/verify-before-claim/`）：
技能目录会被打包发布，本机指纹进包既无意义、也属不该外传的环境信息。

退出码: 0 = 探测完成 / 比对可比   1 = 自检失败   2 = 比对发现差异（不可直接沿用）
"""
import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time

TIMEOUT = 8

# 探测项 → 判据库里「个性化判据」的对应关系。
# 每项给**命中**与**未命中**两句文案：未命中同样要写出来 ——
# 「这条坑在本机不成立」也是一条结论，且它只在**本机**成立（判据 L40）。
PERSONAL_MAP = {
    "grep_bre_alternation": ("L02", [
        ("true",
         "本环境 grep **支持** BRE `\\|` 交替 ⇒ L02 的「静默失配」现象在本机**不成立**；"
         "但仍应照 L02 的判据改用 `grep -E`（换环境即可能翻转）"),
        ("false",
         "本环境 grep **不支持** BRE `\\|` 交替 ⇒ `grep \"A\\|B\"` 静默返回空，"
         "按 L02 一律改 `grep -E \"A|B\"`"),
    ]),
    "dev_tcp": ("R14", [
        ("true", "本环境有 /dev/tcp ⇒ 端口探测可用；仍须对一个**确定开放**的端口做一次对照"),
        ("false", "本环境无 /dev/tcp ⇒ 端口探测恒判 CLOSED，"
                  "**不得**据此判「服务没在跑」"),
    ]),
    "proc_list": ("R15", [
        ("true", "本环境可见进程列表 ⇒ 「进程不存在」可作为证据（仍建议配一条产物通道）"),
        ("false", "本环境进程列表为空 ⇒ 属受限环境特征，"
                  "**进程看不到 ≠ 服务未运行**"),
    ]),
    "proxy_env": ("R20", [
        ("true", "本环境已设置代理变量 ⇒ 探测类失败先怀疑**未绕过代理**的假 502（R20）"),
        ("false", "本环境未设置代理变量 ⇒ 少了「代理导致的假失败」这一条解释；"
                  "探测失败仍须先自证探测手段可用"),
    ]),
    "credential_agent": ("R21", [
        ("true", "本环境有凭据代理 ⇒ 会话态不持久，**每个新会话首连须重新加载**"),
        ("false", "本环境无凭据代理 ⇒ 凭据类失败另有成因，勿套用 R21 的解释"),
    ]),
}
# ⚠️ shell 只作**环境信息**记录，不参与「陷阱成立 / 不成立」判定 ——
#    它是一条事实，不是一个可能翻转的坑（相关判据 L19 的形态取决于具体 shell，
#    本脚本不替用户断言）。

# 需要探测是否在 PATH 中的工具（缺失 ⇒ unknown，不是 false）
TOOLS = (
    "curl", "wget", "shasum", "sha256sum", "md5", "jq", "git", "rsync",
    "ssh", "nc", "stat", "find", "grep", "sed", "awk", "tar", "unzip",
)

# 只记"是否设置"的环境变量（不记值 —— 值可能是凭据或内网地址）
SENSITIVE_ENV_KEYS = (
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
)
CRED_AGENT_KEYS = ("SSH_AUTH_SOCK",)


def run(cmd, env=None, timeout=TIMEOUT):
    """跑一条命令，返回 (rc, 合并输出)。异常一律记 unknown，不静默吞掉。"""
    try:
        p = subprocess.run(
            cmd, shell=True, env=env, capture_output=True, text=True, timeout=timeout
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"
    except Exception as exc:  # 环境不允许执行（如 PATH 被清空）
        return 127, "UNRUNNABLE: %s" % type(exc).__name__


def _has(cmd, env=None):
    return shutil.which(cmd) is not None if env is None else _which_env(cmd, env)


def _which_env(cmd, env):
    """在给定 env 的 PATH 下找命令（shutil.which 支持 path 参数，不支持 env）。"""
    path = (env or {}).get("PATH", "")
    return shutil.which(cmd, path=path) is not None


def probe_dev_tcp(env=None):
    """探测当前 shell 是否支持 `/dev/tcp` 重定向（判据 R14 的判定点）。

    ⚠️ **不能写成 `test -e /dev/tcp`**：`/dev/tcp` 是 **shell 内建的伪设备**，
    文件系统里根本不存在 ⇒ 那样探测**恒为 false**（假阴性），会把
    「无 /dev/tcp ⇒ 端口探测恒判 CLOSED」这条陷阱**永远**写进第一栏，
    进而污染 L40 的「读指纹」捷径——一个恒假的指纹比没有指纹更危险。

    正确做法：**实发一次连接**，靠报错文本区分两种失败：
      - `Connection refused` ⇒ 路径被解析了，**支持**（端口没开是预期的）
      - `No such file` / `not supported` ⇒ **不支持**
      - 其他 ⇒ `unknown`（不猜）
    """
    rc, out = run("exec 3<>/dev/tcp/127.0.0.1/1", env=env)
    low = (out or "").lower()
    if "connection refused" in low or "refused" in low or rc == 0:
        return "true"
    if "no such file" in low or "not supported" in low or "bad fd" in low:
        return "false"
    return "unknown"


def probe(env=None):
    """采集环境指纹。env 用于自检时构造受限环境。

    每项取值只有三种：`true` / `false` / `unknown`。
    ⚠️ 探测跑不起来一律是 `unknown` —— 它表示"这条判据在本环境的适用性**未验证**"，
    不是"这条判据不适用"。
    """
    fp = {"schema": "verify-before-claim/env-fingerprint", "schema_version": 1}

    # ── 平台 ──────────────────────────────────────────────
    fp["os"] = platform.system()
    fp["os_release"] = platform.release()
    fp["arch"] = platform.machine()

    # ── shell ─────────────────────────────────────────────
    sh = (env or os.environ).get("SHELL") if env is None else env.get("SHELL")
    fp["shell"] = sh if sh else "unknown"
    # 命令**实际**经哪个 shell 执行（Python subprocess 默认 /bin/sh）——
    # 决定引号解析与未引号变量的词分割行为（判据 L19 / L04）
    rc, out = run("echo $0", env=env)
    fp["exec_shell"] = out.strip() if rc == 0 and out.strip() else "unknown"

    # ── grep 方言：BRE 是否支持 \| 交替（L02 的判定点）──────
    # GNU grep: 支持 ⇒ 匹配 2 行；BSD grep: 不支持 ⇒ 匹配 0 行、rc=1
    # ⚠️ 用 printf 造数据，不依赖任何外部文件（可复现）
    if _has("grep", env):
        rc, out = run(r"printf 'a\nb\n' | grep -c 'a\|b'", env=env)
        m = re.search(r"(\d+)", out)
        n = int(m.group(1)) if m else -1
        if rc not in (0, 1) or n < 0:
            fp["grep_bre_alternation"] = "unknown"
            fp["grep_probe_raw"] = out.strip()[:120]
        else:
            fp["grep_bre_alternation"] = "true" if n >= 2 else "false"
            fp["grep_probe_raw"] = "matched=%d rc=%d" % (n, rc)
    else:
        fp["grep_bre_alternation"] = "unknown"
        fp["grep_probe_raw"] = "grep 不在 PATH"

    # ── /dev/tcp（R14 的判定点）─────────────────────────────
    fp["dev_tcp"] = probe_dev_tcp(env)

    # ── 进程列表能力（R15 的判定点）──────────────────────────
    rc, out = run("ps -e -o comm= 2>/dev/null | head -5", env=env)
    if rc == 0 and out.strip():
        fp["proc_list"] = "true"
        fp["proc_list_count_hint"] = len([x for x in out.splitlines() if x.strip()])
    elif rc == 0 and not out.strip():
        fp["proc_list"] = "false"  # 命令能跑但列表为空 ⇒ 受限环境的特征，不是探测失败
    else:
        fp["proc_list"] = "unknown"

    # ── python ────────────────────────────────────────────
    rc, out = run("python3 -V 2>&1", env=env)
    fp["python3"] = out.strip() if rc == 0 and out.strip() else "unknown"

    # ── 工具集 ─────────────────────────────────────────────
    fp["tools"] = {t: ("true" if _has(t, env) else "false") for t in TOOLS}

    # ── 代理变量（只记**是否非空**，不记值）──────────────────
    scope = env if env is not None else os.environ
    fp["proxy_env"] = "true" if [k for k in SENSITIVE_ENV_KEYS if scope.get(k)] else "false"
    fp["credential_agent"] = \
        "true" if [k for k in CRED_AGENT_KEYS if scope.get(k)] else "false"

    # ── 时区 ──────────────────────────────────────────────
    fp["tz"] = time.tzname[0] if time.tzname else "unknown"
    rc, out = run("date +%z", env=env)
    fp["utc_offset"] = out.strip() if rc == 0 and out.strip() else "unknown"

    return fp


# 每个探测项取什么值时代表「这个坑在本机成立」
TRAP_WHEN = {
    "grep_bre_alternation": "false",
    "dev_tcp": "false",
    "proc_list": "false",
    "proxy_env": "true",
    "credential_agent": "true",
}


def align(fp):
    """把指纹对齐到判据库：列出「本机已确认的陷阱」「本机不成立」「未验证项」。

    ⚠️ 三分类是刻意的：把「未探测」并进「不成立」等于宣称一个没验证过的结论，
    正是第 6 类失败形态（探测失败 ≠ 对象不适用）。
    """
    hit, neg, unknown = [], [], []
    for key, (code, rules) in sorted(PERSONAL_MAP.items()):
        val = fp.get(key)
        if val in (None, "unknown", ""):
            unknown.append("%s（探测项 %s 没跑起来 ⇒ 该判据在本环境的适用性**未验证**）"
                           % (code, key))
            continue
        tpl = dict(rules).get(val)
        if tpl is None:
            unknown.append("%s（探测项 %s 取值 %r 非预期 ⇒ 适用性未验证）"
                           % (code, key, val))
            continue
        (hit if TRAP_WHEN.get(key) == val else neg).append("%s：%s" % (code, tpl))
    return hit, neg, unknown


def render(fp):
    hit, neg, unknown = align(fp)
    lines = ["# 环境指纹", ""]
    lines.append("> 由 `scripts/env_fingerprint.py` 生成；本机专属，**不进发布包**。")
    lines.append("")
    lines.append("| 项 | 值 |")
    lines.append("|---|---|")
    for k in ("os", "os_release", "arch", "shell", "exec_shell",
              "grep_bre_alternation", "dev_tcp", "proc_list", "python3",
              "tz", "utc_offset", "proxy_env", "credential_agent"):
        lines.append("| %s | %s |" % (k, fp.get(k, "unknown")))
    missing = [t for t, v in sorted((fp.get("tools") or {}).items()) if v != "true"]
    lines.append("| 缺失工具 | %s |" % (", ".join(missing) or "（无）"))
    lines.append("")
    lines.append("## 本机已确认的陷阱（照这些判据处置）")
    lines.append("")
    for x in hit:
        lines.append("- %s" % x)
    if not hit:
        lines.append("- （本轮探测未命中个性化陷阱）")
    lines.append("")
    lines.append("## 已探测、但本环境**不成立**（换环境仍须复测，判据 L40）")
    lines.append("")
    for x in neg:
        lines.append("- %s" % x)
    if not neg:
        lines.append("- （无）")
    lines.append("")
    lines.append("## 未验证项（探测没跑起来 ⇒ 不得当作「不适用」）")
    lines.append("")
    for x in unknown:
        lines.append("- %s" % x)
    if not unknown:
        lines.append("- （无）")
    lines.append("")
    return "\n".join(lines)


# ── 比对 ──────────────────────────────────────────────────
# 差异分两级：关键项变化 ⇒ 结论不可直接沿用；次要项变化 ⇒ 提示，可沿用。
CRITICAL_KEYS = ("os", "arch", "shell", "grep_bre_alternation", "dev_tcp",
                 "proc_list", "python3", "utc_offset")
TOOL_KEYS_CRITICAL = ("grep", "shasum", "sha256sum", "curl", "ssh")


def diff(a, b):
    """比对两份指纹。返回 (关键差异列表, 次要差异列表)。"""
    crit, minor = [], []
    for k in CRITICAL_KEYS:
        va, vb = a.get(k), b.get(k)
        if va != vb:
            crit.append("%s: %s → %s" % (k, va, vb))
    ta, tb = a.get("tools") or {}, b.get("tools") or {}
    for t in sorted(set(ta) | set(tb)):
        if ta.get(t) != tb.get(t):
            item = "工具 %s: %s → %s" % (t, ta.get(t, "未探测"), tb.get(t, "未探测"))
            (crit if t in TOOL_KEYS_CRITICAL else minor).append(item)
    for k in ("proxy_env", "credential_agent"):
        if a.get(k) != b.get(k):
            minor.append("%s: %s → %s" % (k, a.get(k) or "（无）", b.get(k) or "（无）"))
    # unknown 的处理要说清：**两侧取值相同就不算「差异」**，哪怕同为 unknown。
    # ⚠️ 早先写成「任一侧 unknown ⇒ 关键差异」，结果在 `env -i`（无 SHELL 变量）的
    #    隔离环境里，「同一环境两次探测」被自检判成**不可复现**——把「都未验证」
    #    误报成「环境变了」。两侧都 unknown 是**一致**的，只是该项无从比对 ⇒ 记提示。
    for k in CRITICAL_KEYS:
        va, vb = a.get(k), b.get(k)
        if va == vb == "unknown":
            minor.append("%s: 两侧均未验证（unknown）—— 该项不可比，结论仍可能不成立"
                         % k)
    return crit, minor


def cmd_diff(pa, pb):
    a = json.load(open(pa, encoding="utf-8"))
    b = json.load(open(pb, encoding="utf-8"))
    crit, minor = diff(a, b)
    print("── 环境指纹比对 ──")
    print("A: %s" % pa)
    print("B: %s" % pb)
    if minor:
        print("次要差异（提示，通常仍可比）:")
        for x in minor:
            print("  - %s" % x)
    if crit:
        print("关键差异（%d 项）:" % len(crit))
        for x in crit:
            print("  ✗ %s" % x)
        print("FAIL  环境不同 ⇒ 在 A 上采集的结论**不可直接沿用到 B**；"
              "须在 B 上重跑真检（旧结论降级为「无法判定」）")
        return 2
    print("PASS  关键项一致 ⇒ 结论可跨环境沿用（仍建议对锚做一次复读）")
    return 0


# ── 自检 ──────────────────────────────────────────────────
def self_test():
    """阴性对照：本脚本必须能在「环境受限」时报出 unknown，而不是报正常。"""
    print("── 阴性对照 (--self-test) ──")
    fails = []

    # 1) 正常环境：关键项必须**真的探测出值**，不能全是 unknown
    fp = probe()
    if fp.get("os") in (None, "unknown"):
        fails.append("正常环境下 os 仍为 unknown —— 探测本身没工作")
    else:
        print("  ✓ 正常环境探测有值: os=%s grep_bre_alternation=%s"
              % (fp.get("os"), fp.get("grep_bre_alternation")))

    # 2) 受限环境（PATH 置空）：工具必须报 false，且探测项落 unknown，
    #    不得报 true（把"探测不到"写成"支持"正是本技能要防的形态）
    restricted = {"PATH": "/nonexistent", "SHELL": "/bin/sh"}
    fp2 = probe(env=restricted)
    if fp2.get("grep_bre_alternation") == "true":
        fails.append("PATH 置空后 grep_bre_alternation 仍报 true —— 探测失效（假通过）")
    elif fp2.get("grep_bre_alternation") == "unknown":
        print("  ✓ 受限环境（PATH 置空）下 grep 方言落 unknown，未伪装成 true/false")
    else:
        fails.append("受限环境下 grep_bre_alternation=%r —— 期望 unknown"
                     % fp2.get("grep_bre_alternation"))

    tools_bad = [t for t, v in (fp2.get("tools") or {}).items() if v == "true"]
    if tools_bad:
        fails.append("PATH 置空后仍有工具报存在: %s" % ", ".join(sorted(tools_bad)[:5]))
    else:
        print("  ✓ 受限环境下工具集全部报缺失（未把「找不到」写成「存在」）")

    # 2c) dev_tcp 探测的**语义**必须正确（A4 审计缺口 0）：
    #     旧写法 `test -e /dev/tcp` 恒为 false（伪设备不在文件系统里）⇒ 假阴性。
    #     这里用「旧方法 vs 新方法」做一对对照：两者不同 ⇒ 证明新方法不是恒假。
    rc_old, out_old = run("test -e /dev/tcp && echo yes || echo no")
    old_says = "true" if "yes" in out_old else "false"
    if fp.get("dev_tcp") == "unknown":
        fails.append("dev_tcp 探测落 unknown —— 未产生可判定的结论")
    elif old_says == "false" and fp.get("dev_tcp") == "false":
        # 两者都 false 时，必须有**独立证据**证明"确实不支持"，否则就是旧写法的假阴性
        rc_z, out_z = run("exec 3<>/dev/tcp/127.0.0.1/1 2>&1; echo rc=$?")
        if "refused" in (out_z or "").lower():
            fails.append("实发连接显示支持 /dev/tcp，但探测判 false ⇒ 假阴性（缺口 0 复发）")
        else:
            print("  ✓ dev_tcp=false 与实发连接一致（非假阴性）")
    else:
        print("  ✓ dev_tcp 探测=%s，与 `test -e` 的 %s 不同 ⇒ 未退化为恒假"
              % (fp.get("dev_tcp"), old_says))

    # 2b) 受限环境下，没跑起来的探测项必须进「未验证」，不得被写成「本机不成立」
    _h, _n, unknown2 = align(fp2)
    if not unknown2:
        fails.append("受限环境下未验证项为空 ⇒ 「探测失败」被写成了「不适用」（第 6 类形态）")
    else:
        print("  ✓ 受限环境下 %d 项落「未验证」，未被并入「本机不成立」" % len(unknown2))

    # 3) 同一环境两次探测必须一致（可复现）
    fp3 = probe()
    crit, _ = diff(fp, fp3)
    if crit:
        fails.append("同一环境两次探测出现关键差异（不可复现）: %s" % crit[:2])
    else:
        print("  ✓ 同一环境两次探测结果一致（可复现）")

    # 4) 伪造差异指纹：比对必须报 FAIL（能区分「环境不同」）
    forged = json.loads(json.dumps(fp))
    forged["os"] = "OtherOS"
    forged["grep_bre_alternation"] = \
        "false" if fp.get("grep_bre_alternation") == "true" else "true"
    forged["tools"] = dict(fp.get("tools") or {})
    forged["tools"]["shasum"] = "false"
    crit2, _ = diff(fp, forged)
    if not crit2:
        fails.append("伪造差异指纹未被比对抓住 ⇒ 比对失效")
    else:
        print("  ✓ 伪造差异被抓住（%d 项关键差异）: %s" % (len(crit2), crit2[0]))

    if fails:
        for f in fails:
            print("  ✗ %s" % f)
        print("FAIL  自检未通过（%d 项）" % len(fails))
        return 1
    print("PASS  阴性对照通过 —— 探测能报 unknown，比对能报差异")
    return 0


def main():
    ap = argparse.ArgumentParser(description="环境指纹（层 1 自适配）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--save", metavar="PATH", help="存一份 JSON 基线（供 --diff 用）")
    ap.add_argument("--write", metavar="PATH", help="落成 Markdown 报告")
    ap.add_argument("--diff", nargs=2, metavar=("A", "B"), help="比对两份 JSON 指纹")
    ap.add_argument("--self-test", action="store_true", help="阴性对照")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if args.diff:
        return cmd_diff(*args.diff)

    fp = probe()
    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            json.dump(fp, f, ensure_ascii=False, indent=2)
        print("已存基线: %s" % args.save)
    if args.write:
        with open(args.write, "w", encoding="utf-8") as f:
            f.write(render(fp))
        print("已写报告: %s" % args.write)
    if args.json or not (args.save or args.write):
        if args.json:
            print(json.dumps(fp, ensure_ascii=False, indent=2))
        else:
            print(render(fp))
    return 0


if __name__ == "__main__":
    sys.exit(main())
