import csv, sys, statistics as st
from collections import defaultdict

rows = list(csv.reader(open(sys.argv[1])))
d = defaultdict(lambda: defaultdict(list))  # (kind, metric) -> pin -> [values]
unit = {}
for rep, kind, pin, metric, val, u in rows:
    if rep == "0" or val == "":
        continue
    d[(kind, metric)][pin].append(float(val))
    unit[(kind, metric)] = u

# which direction is "worse"
def higher_is_better(m):
    return m.endswith(("_down", "up1", "_pps", "_ratio")) or "tput" in m and "cpu" not in m

def classify(kind, m, o, n):
    mo, mn = st.median(o), st.median(n)
    so, sn = max(o) - min(o), max(n) - min(n)
    spread = max(so, sn)
    if mo == 0 and mn == 0:
        return mo, mn, 0.0, "ok"
    rel = (mn - mo) / mo * 100 if mo else float("inf")
    hib = higher_is_better(m)
    worse_rel = -rel if hib else rel          # >0 means worse
    worse_abs = abs(mn - mo)
    flag = "ok"
    if "_p50" in m or m in ("rtt_max",):
        if worse_rel > 10 and worse_abs > 0.2 and worse_abs > spread:
            flag = "FLAG"
    elif "_p99" in m:
        if worse_rel > 25 and worse_abs > 1.0 and worse_abs > spread:
            flag = "FLAG"
    elif m in ("ttfb_fail",) or m.endswith("_lost"):
        if mn > mo:
            flag = "FLAG"
    else:
        if worse_rel > 5 and worse_abs > spread:
            flag = "FLAG"
    return mo, mn, rel, flag

kinds = ["direct", "vision", "reality", "vmess", "ss2022", "hy2"]
print(f"{'kind':8} {'metric':22} {'old med':>10} {'new med':>10} {'delta%':>8} {'oldspread':>10} {'newspread':>10}  verdict")
flags = []
for kind in kinds:
    ms = sorted({m for (k, m) in d if k == kind})
    for m in ms:
        o, n = d[(kind, m)]["old"], d[(kind, m)]["new"]
        if not o or not n:
            continue
        mo, mn, rel, fl = classify(kind, m, o, n)
        print(f"{kind:8} {m:22} {mo:10.3f} {mn:10.3f} {rel:8.1f} {max(o)-min(o):10.3f} {max(n)-min(n):10.3f}  {fl}")
        if fl == "FLAG":
            flags.append((kind, m, mo, mn, rel))
print()
print("FLAGS:", len(flags))
for f in flags:
    print("  ", f)
