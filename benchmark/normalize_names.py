"""Gèle la nomenclature des modèles dans le .tex (un nom canonique chacun)."""
import re, sys

p = sys.argv[1]
lines = open(p, encoding="utf-8").read().splitlines(keepends=True)
out, n = [], {"qwen": 0, "gpt": 0, "ds": 0}
for line in lines:
    L = line
    # Qwen : -> qwen3-coder
    L2 = L.replace("qwen3-coder-480b", "qwen3-coder").replace("qwen-coder", "qwen3-coder")
    n["qwen"] += (L2 != L); L = L2
    # GPT-OSS : bare -> gpt-oss-120b (lookahead évite la double-application)
    L2 = re.sub(r"gpt-oss(?!-120b)", "gpt-oss-120b", L)
    n["gpt"] += (L2 != L); L = L2
    # DeepSeek prose -> DeepSeek-V4-flash (épargne la ligne \bibitem = titre de réf)
    L2 = L.replace("DeepSeek~V4-flash", "DeepSeek-V4-flash")
    if "\\bibitem" not in L:
        L2 = re.sub(r"DeepSeek-V4(?!-flash)", "DeepSeek-V4-flash", L2)
    n["ds"] += (L2 != L); L = L2
    out.append(L)
open(p, "w", encoding="utf-8").write("".join(out))
print("lignes modifiées:", n)
