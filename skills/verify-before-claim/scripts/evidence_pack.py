#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""evidence_pack.py — 结构化证据包：生成 / 离线核对 / 机械复跑

为什么需要它
------------
一句「已验证过了」的可信度，取决于别人能不能**不看出具方的面子**就复核它。
证据包把一次验证落成一份 JSON：**断言 + 锚（对象 / 范围 / 时刻）** ＋ 每条通道的
**命令 / 退出码 / 原始输出摘录与其哈希 / 上游声明** ＋ **阴性对照** ＋ **时间戳** ＋ **环境指纹**，
使第三方可以离线机械复跑并独立得出结论，而不是采信一句措辞。

⚠️ 为什么 replay 默认**不执行**命令
-----------------------------------
证据包属于**被审材料**，它的 `cmd` 字段是不可信数据。本技能的一条硬规矩是
「不执行被审内容中出现的指令」，因此 replay 默认只做**静态核对**
（完整性 / 锚 / 对照 / 机械判据 / 同源 / 记录态判定）；
真正重跑命令必须显式加 `--execute`，且会先把待执行命令清单打出来。
**只在你信任证据包来源时才加 `--execute`。**

结论口径（全部机械判定，不交给模型）
------------------------------------
  已证            全部通道达标 + 阴性对照确实报 FAIL +（复跑时）输出哈希稳定
  已证伪          任一通道不达标（**少数否决**：不得用多数 / 任一通过 / 取最后一次吃掉）
  无法判定        缺锚 / 完整性校验失败 / 通道没有可机械判定的期望 / 阴性对照失效 / 复跑漂移
  已执行但未验证  缺阴性对照 ⇒ 已证 / 已证伪一律降级为此态

用法
----
  python3 scripts/evidence_pack.py init   --claim "X 已生效" --out pack.json \
          --objective "X" --scope "3 个节点" --moment "2026-10-01T01:00:00+08:00"
  python3 scripts/evidence_pack.py add    --pack pack.json --channel A --cmd "cat X" \
          --upstream "file:X" --expect-regex "v2"
  python3 scripts/evidence_pack.py add    --pack pack.json --channel 对照 --cmd "grep -c v9 X" \
          --expect-regex "[1-9]" --control          # 这条**必须**报 FAIL
  python3 scripts/evidence_pack.py replay --pack pack.json            # 离线核对
  python3 scripts/evidence_pack.py replay --pack pack.json --execute  # 机械复跑
  python3 scripts/evidence_pack.py --self-test   # 阴性对照：证明本工具能报非「已证」

退出码: 0 = 结论为「已证」   1 = 结论非「已证」（已证伪 / 无法判定 / 已执行但未验证）
       2 = 用法或环境错误（无结论）
"""
import argparse
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import tempfile
import shutil
from datetime import datetime

SCHEMA = "vbc-evidence-pack/1"
EXCERPT_LIMIT = 600
DEFAULT_TIMEOUT = 60
TIMEOUT_RC = 124
# 第 7 类形态的三项锚：缺任一项 ⇒ 断言指不到对象，后面所有步骤无从下手
ANCHORS = (("objective", "对象标识"), ("scope", "范围枚举"), ("moment", "读取时刻"))


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def norm_cmd(cmd):
    return re.sub(r"\s+", " ", (cmd or "")).strip()


def env_fingerprint():
    """记录时的环境指纹（用于发现「换个环境复跑」这种不可比情形）。"""
    return {
        "host": socket.gethostname(),
        "user": os.environ.get("USER") or os.environ.get("LOGNAME") or "",
        "cwd": os.getcwd(),
        "python": platform.python_version(),
        "platform": platform.platform(),
    }


def run_cmd(cmd, timeout=DEFAULT_TIMEOUT):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"")
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return TIMEOUT_RC, out, "TIMEOUT after %ss" % timeout


def evaluate(cmd, regex, expect_rc, timeout=DEFAULT_TIMEOUT):
    """跑一条通道，把可复核的事实落下来（不记录任何「结论」）。"""
    rc, out, err = run_cmd(cmd, timeout)
    matched = (rc == expect_rc) and (regex is None or re.search(regex, out) is not None)
    return {
        "observed_at": now_iso(),
        "env": env_fingerprint(),
        "rc": rc,
        "matched": matched,
        "stdout_sha256": sha256(out),
        "stderr_sha256": sha256(err),
        "stdout_excerpt": out[:EXCERPT_LIMIT],
        "stderr_excerpt": err[:200],
    }


# ── 证据包的读写 ────────────────────────────────────────────────────────────

def new_pack(claim, objective="", scope="", moment=""):
    pack = {
        "schema": SCHEMA,
        "claim": claim,
        "anchors": {"objective": objective or "", "scope": scope or "", "moment": moment or ""},
        "created_at": now_iso(),
        "env": env_fingerprint(),
        "channels": [],
        "pack_sha256": "",
    }
    return sign(pack)


def _canonical(pack):
    body = {k: v for k, v in pack.items() if k != "pack_sha256"}
    return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sign(pack):
    """对证据包签名：任何事后改动都会让 pack_sha256 对不上。"""
    pack["pack_sha256"] = sha256(_canonical(pack))
    return pack


def integrity_ok(pack):
    return bool(pack.get("pack_sha256")) and pack.get("pack_sha256") == sha256(_canonical(pack))


def add_entry(pack, channel, cmd, upstream="", regex=None, expect_rc=0,
              control=False, timeout=DEFAULT_TIMEOUT, rc_set=False):
    entry = {
        "channel": channel,
        "cmd": cmd,
        "upstream": upstream or "",
        "control": bool(control),
        # ⚠️ `rc_set` 记录「期望退出码是**显式**给的」—— 只认 regex 会把
        #    `test -f` / `grep -q` / `systemctl is-active` 这类**靠退出码判定**的通道
        #    误降级成「没有可机械判定的期望」（与判据 L38 冲突，A4 审计缺口 0b）。
        "expect": {"rc": expect_rc, "regex": regex, "rc_set": bool(rc_set)},
    }
    entry.update(evaluate(cmd, regex, expect_rc, timeout))
    pack["channels"].append(entry)
    sign(pack)  # 每加一条就重签：改动不留痕会让「事后篡改」无法被发现
    return entry


def load_pack(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_pack(pack, path):
    sign(pack)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(pack, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return pack


# ── 判定 ────────────────────────────────────────────────────────────────────

def entry_pass(control, matched):
    """通道是否「达标」。

    ⚠️ 阴性对照的达标定义是**反的**：它必须报 FAIL。
    对照报 PASS 说明检查器此刻区分不出对错，它对真检给出的 PASS 也就不可采信。
    """
    return (not matched) if control else matched


def detect_same_source(channels):
    """找出同源通道（命令相同 或 声明的上游相同），并数出独立通道数。

    ⚠️ 阴性对照**不参与**同源判定——它本来就该读同一个对象，把它算进「交叉验证」
    只会让「有对照」被误读成「有第二条独立通道」。
    """
    channels = [e for e in channels if not e.get("control")]
    pairs = []
    for i in range(len(channels)):
        for j in range(i + 1, len(channels)):
            a, b = channels[i], channels[j]
            if norm_cmd(a.get("cmd")) == norm_cmd(b.get("cmd")):
                pairs.append((a.get("channel"), b.get("channel"), "命令相同"))
            elif a.get("upstream") and a.get("upstream") == b.get("upstream"):
                pairs.append((a.get("channel"), b.get("channel"), "上游相同（%s）" % a["upstream"]))
    keys = set()
    for e in channels:
        if e.get("upstream"):
            keys.add(("up", e["upstream"]))
        else:
            keys.add(("cmd", norm_cmd(e.get("cmd"))))
    return pairs, len(keys)


def replay(pack, execute=False, timeout=DEFAULT_TIMEOUT):
    """离线核对（默认）/ 机械复跑（--execute）。返回结论字典。"""
    warnings = []
    detail = []
    channels = pack.get("channels") or []

    def done(verdict, reason, confidence="—"):
        return {
            "verdict": verdict,
            "reason": reason,
            "confidence": confidence,
            "warnings": warnings,
            "channels": detail,
            "executed": bool(execute),
            "claim": pack.get("claim", ""),
        }

    # ① 完整性：被改过的证据包，里面写什么都不作数
    if not pack.get("pack_sha256"):
        return done("无法判定", "证据包未签名（pack_sha256 缺失）—— 完整性无从校验")
    if not integrity_ok(pack):
        return done("无法判定",
                    "证据包内容与 pack_sha256 不符 —— 记录后被改动过，任何结论都不可采信")

    # ② 锚（第 7 类）：缺一项即无法判定，不进后续
    anchors = pack.get("anchors") or {}
    missing = [label for key, label in ANCHORS if not str(anchors.get(key) or "").strip()]
    if missing:
        return done("无法判定",
                    "缺锚：%s —— 断言指不到对象 / 范围 / 时刻，后面全部步骤无从下手" % "、".join(missing))
    if not channels:
        return done("无法判定", "证据包没有任何通道 —— 无证据")

    # ③ 每条通道必须带**可机械判定**的期望；只有结论、没有判据的证据不可复核
    #    ⚠️ 「正则 **或** 显式期望退出码」任一即算有判据（判据 L38 明写二者皆可）。
    #       只看 regex 会把靠退出码判定的通道误降级为无法判定。
    for e in channels:
        exp = e.get("expect") or {}
        if not e.get("control") and not (exp.get("regex") or exp.get("rc_set")):
            return done("无法判定",
                        "通道「%s」没有可机械判定的期望（只有结论、没有判据）—— 证据不可复核"
                        % e.get("channel"))

    # ④ 同源检测（警告级；同源 ⇒ 置信度按单通道计）
    pairs, indep = detect_same_source(channels)
    for a, b, why in pairs:
        warnings.append("通道「%s」与「%s」同源（%s）—— 该一致性不含信息，不得写「已交叉验证」" % (a, b, why))
    if len(channels) >= 2 and indep >= 2 and not pairs:
        confidence = "多通道（通道独立，可作交叉验证）"
    else:
        confidence = "单通道计（不得写「已交叉验证」）"
    if execute:
        cur_env = env_fingerprint()
        rec_env = pack.get("env") or {}
        if rec_env.get("host") and rec_env.get("host") != cur_env.get("host"):
            warnings.append("环境指纹不同（记录于 %s，复跑于 %s）—— 复跑可比性下降"
                            % (rec_env.get("host"), cur_env.get("host")))

    # ⑤ 阴性对照必须存在（缺 ⇒ 已证 / 已证伪一律降级为「已执行但未验证」）
    if not any(e.get("control") for e in channels):
        return done("已执行但未验证",
                    "缺阴性对照：没有一条「必然报 FAIL」的对照 ⇒ 已证 / 已证伪一律降级为「已执行但未验证」",
                    confidence)

    # ⑥ 复跑（可选）：对照必须仍然报 FAIL；真检输出不得漂移
    if execute:
        for e in channels:
            exp = e.get("expect") or {}
            obs = evaluate(e.get("cmd"), exp.get("regex"), exp.get("rc", 0), timeout)
            control = bool(e.get("control"))
            if not control and obs["stdout_sha256"] != e.get("stdout_sha256"):
                warnings.append("通道「%s」复跑输出与记录不一致（哈希漂移）" % e.get("channel"))
                return done("无法判定",
                            "通道「%s」复跑输出与记录不一致（哈希漂移）—— 环境或对象已变，旧结论不可沿用"
                            % e.get("channel"), confidence)
            detail.append({
                "channel": e.get("channel"),
                "control": control,
                "basis": "复跑",
                "rc": obs["rc"],
                "matched": obs["matched"],
                "state": ("对照成立（报 FAIL）" if not obs["matched"] else "对照失效（报 PASS）")
                          if control else ("PASS" if obs["matched"] else "FAIL"),
                "sha": obs["stdout_sha256"][:12],
                "sha_stable": (obs["stdout_sha256"] == e.get("stdout_sha256")) if not control else None,
                "cmd": e.get("cmd"),
            })
    else:
        for e in channels:
            control = bool(e.get("control"))
            matched = bool(e.get("matched"))
            detail.append({
                "channel": e.get("channel"),
                "control": control,
                "basis": "记录",
                "rc": e.get("rc"),
                "matched": matched,
                "state": ("对照成立（报 FAIL）" if not matched else "对照失效（报 PASS）")
                          if control else ("PASS" if matched else "FAIL"),
                "sha": str(e.get("stdout_sha256"))[:12],
                "sha_stable": None,
                "cmd": e.get("cmd"),
            })

    # ⑦ 对照必须**真的报了 FAIL**（记录态与复跑态都要判；只报 PASS 的对照等于没有对照）
    for d in detail:
        if d["control"] and d["matched"]:
            return done("无法判定",
                        "阴性对照「%s」报了 PASS —— 检查器不能报 FAIL，它对真检给出的 PASS 一律不可采信"
                        % d["channel"], confidence)

    # ⑧ 少数否决：任一真检通道不达标即整体降级，不得用多数 / 任一通过吃掉
    for d in detail:
        if d["control"]:
            continue
        if not entry_pass(False, d["matched"]):
            return done("已证伪",
                        "通道「%s」不达标（少数否决：任一通道 FAIL 即整体降级）—— 实测与断言矛盾"
                        % d["channel"], confidence)

    tail = "，复跑输出哈希稳定" if execute else "（未执行命令，仅静态核对记录）"
    return done("已证", "全部通道达标，且阴性对照确实报 FAIL%s" % tail, confidence)


def render(result):
    mark = {"已证": "✓", "已证伪": "✗", "无法判定": "?", "已执行但未验证": "~"}.get(result["verdict"], "?")
    out = []
    out.append("断言: %s" % result.get("claim", ""))
    out.append("%s 结论: %s" % (mark, result["verdict"]))
    out.append("  依据: %s" % result["reason"])
    out.append("  置信度: %s" % result["confidence"])
    out.append("  核对方式: %s" % ("机械复跑（已执行命令）" if result.get("executed") else "离线核对（未执行命令）"))
    out.append("  通道:")
    for d in result["channels"]:
        tag = "对照" if d["control"] else "真检"
        out.append("    - [%s/%s] %-22s rc=%s  %s  sha=%s"
                   % (tag, d["basis"], d["channel"], d["rc"], d["state"], d["sha"]))
    for w in result["warnings"]:
        out.append("  ⚠ %s" % w)
    return "\n".join(out)


# ── 阴性对照：证明本工具自己能报非「已证」 ──────────────────────────────────

def _mk(tmp, name="pack.json"):
    return os.path.join(tmp, name)


def _healthy(tmp, with_control=True):
    """构造一份「应当判已证」的证据包。"""
    d = os.path.join(tmp, "obj")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "app.txt"), "w") as f:
        f.write("version: v2\n")
    with open(os.path.join(d, "mirror.txt"), "w") as f:
        f.write("version: v2\n")
    pack = new_pack("远端 app 已是 v2", objective="app.txt", scope="本机 1 处", moment=now_iso())
    add_entry(pack, "A-直读内容", "cat %s/app.txt" % d, upstream="file:app.txt", regex="v2")
    add_entry(pack, "B-另一路读数", "cat %s/mirror.txt" % d, upstream="file:mirror.txt", regex="v2")
    if with_control:
        # 对照：查一个必然不存在的串 ⇒ 必须报 FAIL
        add_entry(pack, "对照-查不存在的串", "grep -c v9 %s/app.txt" % d,
                  upstream="file:app.txt", regex="[1-9]", control=True)
    return pack


def self_test():
    """阴性对照：不合格的证据包必须报非「已证」。

    只报「已证」的工具与「随便什么都能通过」不可区分，因此本函数同时要求：
    **合格样本判已证**（证明它不是恒 FAIL）＋ **每一类缺陷都被抓住**（证明它不是恒 PASS）。
    """
    print("── 阴性对照 (--self-test) ──")
    cases = []

    def case(name, build, expect, execute=False):
        cases.append((name, build, expect, execute))

    def b_healthy(tmp):
        return _healthy(tmp, with_control=True)

    def b_no_control(tmp):
        return _healthy(tmp, with_control=False)

    def b_minority(tmp):
        p = _healthy(tmp)
        add_entry(p, "C-另一处读数", "echo NOT-THERE", upstream="shell:echo", regex="TOTALLY-ABSENT")
        return p

    def b_drift(tmp):
        p = _healthy(tmp)
        p["channels"] = [c for c in p["channels"] if not c.get("control")][:1]
        # ⚠️ 命令本身必须每次跑出不同输出（`date +%s%N`），否则复跑哈希恒稳定，测不出漂移
        add_entry(p, "A-直读内容", "date +%s%N", upstream="file:app.txt", regex=".")
        add_entry(p, "对照-恒定失败", "exit 3", upstream="shell:exit", regex=".", control=True)
        return p

    def b_control_passes(tmp):
        p = _healthy(tmp)
        p["channels"] = [c for c in p["channels"] if not c.get("control")]
        add_entry(p, "对照-本该失败却成功", "echo CONTROL-SHOULD-FAIL",
                  upstream="shell:echo", regex="CONTROL", control=True)
        return p

    def b_no_anchor(tmp):
        p = _healthy(tmp)
        p["anchors"]["objective"] = ""
        return sign(p)

    def b_no_expect(tmp):
        p = _healthy(tmp)
        add_entry(p, "D-只有结论", "echo v2", upstream="shell:echo")
        return p

    def b_rc_only(tmp):
        """只给**期望退出码**、不给正则 —— 按判据 L38 这算有判据，应判「已证」。

        ⚠️ A4 审计缺口 0b：修前会被误降级为「无法判定 / 没有可机械判定的期望」，
        与 L38「正则 / 期望退出码」的口径直接冲突。
        """
        d = os.path.join(tmp, "obj")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "app.txt"), "w") as f:
            f.write("version: v2\n")
        pack = new_pack("app.txt 存在", objective="app.txt", scope="本机 1 处", moment=now_iso())
        add_entry(pack, "A-存在性判定", "test -f %s/app.txt" % d,
                  upstream="file:app.txt", rc_set=True)
        add_entry(pack, "B-另一路存在性", "test -s %s/app.txt" % d,
                  upstream="file:app.txt", rc_set=True)
        add_entry(pack, "对照-查必然不存在的文件",
                  "test -f %s/__nope__" % d, upstream="file:__nope__",
                  control=True, rc_set=True)
        return pack

    def b_tampered(tmp):
        p = _healthy(tmp)
        sign(p)
        p["channels"][0]["rc"] = 0
        p["claim"] = "事后被改过的断言"
        return p  # 改动后不再重签 ⇒ 完整性校验必须失败

    case("合格样本（两条独立通道 + 阴性对照）", b_healthy, "已证")
    case("缺阴性对照 ⇒ 降级", b_no_control, "已执行但未验证")
    case("少数被吞（第三条通道不达标）", b_minority, "已证伪")
    case("复跑漂移（输出哈希对不上）", b_drift, "无法判定", execute=True)
    case("阴性对照报了 PASS ⇒ 检查器失效", b_control_passes, "无法判定")
    case("缺对象锚", b_no_anchor, "无法判定")
    case("只给期望退出码（判据 L38 认可）⇒ 仍算有判据", b_rc_only, "已证")
    case("通道无机械判据（只有结论）", b_no_expect, "无法判定")
    case("证据包被事后改动", b_tampered, "无法判定")

    tmp = tempfile.mkdtemp(prefix="vbc-pack-")
    bad = 0
    try:
        for name, build, expect, execute in cases:
            pack = build(tmp)
            res = replay(pack, execute=execute)
            got = res["verdict"]
            ok = (got == expect)
            bad += 0 if ok else 1
            print("  %s %s → %s（期望 %s）: %s" % ("✓" if ok else "✗", name, got, expect, res["reason"]))
        positive = any(c[0].startswith("合格样本") and c[2] == "已证" for c in cases)
        if not positive:
            print("  ✗ 自证样本集里没有「合格样本 ⇒ 已证」，无法排除恒 FAIL")
            bad += 1
        if bad:
            print("FAIL  阴性对照未通过（%d 项不符合预期）" % bad)
            return 1
        print("  ✓ 合格样本判已证，且 %d 类缺陷全部被抓住 —— 工具能区分对错"
              % (len(cases) - 1))
        print("PASS  阴性对照通过")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="结构化证据包（生成 / 离线核对 / 机械复跑）")
    ap.add_argument("--self-test", action="store_true",
                    help="阴性对照：证明本工具能对不合格的证据包报非「已证」")
    sub = ap.add_subparsers(dest="subcmd")

    p_init = sub.add_parser("init", help="新建证据包（先把断言与三项锚定下来）")
    p_init.add_argument("--claim", required=True, help="要宣告的断言（一句可证伪的话）")
    p_init.add_argument("--objective", default="", help="对象标识（路径 / 主机 / URL / 记录 ID）")
    p_init.add_argument("--scope", default="", help="范围枚举（列出成员的命令或显式枚举）")
    p_init.add_argument("--moment", default="", help="读取时刻（缺省自动取当前时刻）")
    p_init.add_argument("--out", required=True, help="证据包输出路径")

    p_add = sub.add_parser("add", help="追加一条通道（会实际执行 --cmd 并留下哈希）")
    p_add.add_argument("--pack", required=True)
    p_add.add_argument("--channel", required=True, help="通道名（须体现它读的是什么）")
    p_add.add_argument("--cmd", required=True, help="该通道的读取命令")
    p_add.add_argument("--upstream", default="", help="依赖链上游声明（它读了哪个对象/缓存）")
    p_add.add_argument("--expect-regex", default=None, help="输出须匹配的正则（可机械判定的期望）")
    # ⚠️ default=None 而非 0：只有 None 才能区分「显式给了」与「没给」
    p_add.add_argument("--expect-rc", type=int, default=None,
                       help="期望退出码（显式给出即视为可机械判定的期望；默认 0）")
    p_add.add_argument("--control", action="store_true",
                       help="标为阴性对照：这条**必须**报 FAIL，用来证明检查器没坏")
    p_add.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)

    p_rep = sub.add_parser("replay", help="离线核对（默认）/ 机械复跑（--execute）")
    p_rep.add_argument("--pack", required=True)
    p_rep.add_argument("--execute", action="store_true",
                       help="真正重跑证据包内的命令（⚠️ 仅在信任来源时使用）")
    p_rep.add_argument("--json", action="store_true", help="输出 JSON")
    p_rep.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)

    p_show = sub.add_parser("show", help="打印证据包摘要")
    p_show.add_argument("--pack", required=True)

    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if not args.subcmd:
        ap.print_help()
        return 2

    if args.subcmd == "init":
        if os.path.exists(args.out):
            print("用法错误: %s 已存在（不覆盖已有证据：那是销毁证据）" % args.out)
            return 2
        moment = args.moment or now_iso()
        pack = new_pack(args.claim, args.objective, args.scope, moment)
        save_pack(pack, args.out)
        print("已建立证据包: %s" % args.out)
        print("  断言: %s" % args.claim)
        print("  锚: 对象=%r 范围=%r 时刻=%s" % (args.objective, args.scope, moment))
        missing = [l for k, l in ANCHORS if not str(pack["anchors"][k]).strip()]
        if missing:
            print("  ⚠ 缺锚：%s ⇒ 后续 replay 会直接落「无法判定」" % "、".join(missing))
        return 0

    if args.subcmd == "add":
        pack = load_pack(args.pack)
        rc_set = args.expect_rc is not None
        entry = add_entry(pack, args.channel, args.cmd, args.upstream,
                          args.expect_regex,
                          0 if args.expect_rc is None else args.expect_rc,
                          args.control, args.timeout, rc_set=rc_set)
        save_pack(pack, args.pack)
        state = ("对照成立（报 FAIL）" if not entry["matched"] else "⚠ 对照失效（报 PASS）") \
            if args.control else ("PASS" if entry["matched"] else "FAIL")
        print("已追加通道「%s」: rc=%s %s sha=%s"
              % (args.channel, entry["rc"], state, entry["stdout_sha256"][:12]))
        return 0

    if args.subcmd == "replay":
        pack = load_pack(args.pack)
        if args.execute:
            print("⚠️ 即将执行证据包内的 %d 条命令（来源必须是可信方）：" % len(pack.get("channels") or []),
                  file=sys.stderr)
            for e in pack.get("channels") or []:
                print("    - [%s] %s" % ("对照" if e.get("control") else "真检", e.get("cmd")),
                      file=sys.stderr)
        res = replay(pack, execute=args.execute, timeout=args.timeout)
        print(json.dumps(res, ensure_ascii=False, indent=2) if args.json else render(res))
        return 0 if res["verdict"] == "已证" else 1

    if args.subcmd == "show":
        pack = load_pack(args.pack)
        res = replay(pack, execute=False)
        print(render(res))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
