import re, collections, sys
t = open(sys.argv[1], encoding="utf-8").read()
clean = []
for line in t.splitlines():
    out, i, n = [], 0, len(line)
    while i < n:
        if line[i] == "%" and (i == 0 or line[i-1] != "\\"):
            break
        out.append(line[i]); i += 1
    clean.append("".join(out))
s = "\n".join(clean)
errs = []
cb, ce = collections.Counter(re.findall(r"\\begin\{([^}]+)\}", s)), collections.Counter(re.findall(r"\\end\{([^}]+)\}", s))
for env in set(cb) | set(ce):
    if cb[env] != ce[env]:
        errs.append("ENV %s: begin=%d end=%d" % (env, cb[env], ce[env]))
labels = set(re.findall(r"\\label\{([^}]+)\}", s))
refs = set(re.findall(r"\\(?:ref|eqref|autoref)\{([^}]+)\}", s))
for r in refs - labels:
    errs.append("REF non resolue: " + r)
bibs = set(re.findall(r"\\bibitem\{([^}]+)\}", s))
cites = set(k.strip() for g in re.findall(r"\\cite\{([^}]+)\}", s) for k in g.split(","))
for c in cites - bibs:
    errs.append("CITE non resolue: " + c)
if s.count("{") != s.count("}"):
    errs.append("Accolades: %d vs %d" % (s.count("{"), s.count("}")))
print("labels=%d refs=%d bibitems=%d cites=%d env(begin=%d end=%d)" % (
    len(labels), len(refs), len(bibs), len(cb.elements().__length_hint__() if False else sum(cb.values())), 0) if False else "")
print("labels=%d refs=%d | bibitems=%d cites=%d | begins=%d ends=%d" % (
    len(labels), len(refs), len(bibs), len(cites), sum(cb.values()), sum(ce.values())))
print("=== AUCUNE ERREUR ===" if not errs else "=== ERREURS ===")
for e in errs:
    print(" -", e)
