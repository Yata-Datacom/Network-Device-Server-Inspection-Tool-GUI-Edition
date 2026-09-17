"""校验 exe 里打包的代码是否包含指定修复 / 是否还残留旧实现。

用法：
    <venv>/python tools/verify_exe_fixes.py

为什么需要它：**源码改了不代表 exe 里也改了**（打包前忘了重打、或打的是另一份副本）。
⚠️ 两个坑（都踩过）：
  1. 直接对 exe 二进制 grep **无效** —— PYZ 是 zlib 压缩的；
  2. 校验标记要同时收集 `co_consts`（字符串常量、docstring）与 `co_names`（函数名/变量名）；
     写进注释里的字样**不会**进字节码，别拿注释当标记。
PyInstaller 单文件 exe 里：普通模块在 PYZ（`ZlibArchiveReader`），
入口脚本（`nadt`/`__main__`）则在 CArchive 的独立条目里 —— 所以两边都要扫。
"""

import os
import sys
import types

from PyInstaller.archive.readers import CArchiveReader, ZlibArchiveReader

# (exe 路径, [必须存在的修复标记...], [必须消失的旧实现标记...])
EXES = {
    "巡检V5": (r"C:\Users\yata\Documents\coding\network_A\v5\dist\巡检Network Inspection System V5 - For Yata.exe",
              ["_parse_rules_text", "Temperature(C) 列", "顶层优先"],
              ["若取到第一个数字：num"]),
    "巡检V4": (r"C:\Users\yata\Documents\coding\network_A\v4\dist\巡检Network Inspection System V4 - For GCC.exe",
              ["_parse_rules_text", "Temperature(C) 列"],
              ["若取到第一个数字：num"]),
    "NADT": (r"C:\Users\yata\Documents\coding\NADT\dist\NADT - Network Automation Deployment Tool.exe",
             ["_LEFTOVER_RE", "_PLACEHOLDER_RE", "花括号内允许空格"],
             []),
}


def collect(exe: str) -> str:
    """把 exe 里所有 Python 代码对象的字符串常量 + 名字收集成一个大字符串。"""
    car = CArchiveReader(exe)
    tmp = os.path.join(os.environ.get("TEMP", "."), "_verify_exe.pyz")
    chunks = []

    def walk(code, out, depth=0):
        if depth > 12:
            return
        out.update(getattr(code, "co_names", ()))
        for x in getattr(code, "co_consts", ()):
            if isinstance(x, str):
                out.add(x)
            elif isinstance(x, types.CodeType):
                walk(x, out, depth + 1)
            elif isinstance(x, tuple):
                for y in x:
                    if isinstance(y, types.CodeType):
                        walk(y, out, depth + 1)

    for name in [str(x) for x in car.toc.keys()]:
        try:
            data = car.extract(name)
        except Exception:
            continue
        if isinstance(data, tuple):
            data = data[1]
        if not isinstance(data, (bytes, bytearray)):
            continue
        data = bytes(data)
        if name.endswith(".pyz") or name == "PYZ":
            open(tmp, "wb").write(data)
            try:
                zar = ZlibArchiveReader(tmp)
                for key in zar.toc.keys():
                    payload = zar.extract(key)
                    code = payload[1] if isinstance(payload, tuple) else payload
                    acc = set()
                    walk(code, acc)
                    chunks.append("\n".join(sorted(acc, key=len)))
            finally:
                if os.path.exists(tmp):
                    os.remove(tmp)
        else:
            # 入口脚本 / 其他条目：marshalled code 里字符串是 UTF-8，直接按字节搜
            chunks.append(data.decode("utf-8", errors="replace"))
    return "\n".join(chunks)


def main() -> int:
    rc = 0
    for tag, (exe, wants, olds) in EXES.items():
        if not os.path.exists(exe):
            print(f"{tag}: ✗ exe 不存在 {exe}")
            rc = 1
            continue
        blob = collect(exe)
        miss = [w for w in wants if w not in blob]
        left = [o for o in olds if o in blob]
        status = "✓" if not miss and not left else "✗"
        print(f"{tag}: {status}")
        for w in miss:
            print(f"   ✗ 缺修复标记 {w!r}")
        for o in left:
            print(f"   ✗ 仍残留旧实现 {o!r}")
        if miss or left:
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
