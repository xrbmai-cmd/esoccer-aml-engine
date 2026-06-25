#!/usr/bin/env python3
"""
detect_esoccer_aml.py  —  Blue Team: hunt the laundering rings
==============================================================

Part two of the **esoccer-aml-engine**. It ingests the Red Team's synthetic
sportsbook and hunts the matched-betting laundering rings hidden inside it.

The Red Team proved that *single* signals are useless here: "shares an IP" or
"bet opposite sides" each land at ~5% precision because innocent households and
CGNAT users trip them constantly. So this detector scores the **combination**:

    identity linkage (networkx graph)   ── do accounts share IP / device / payout?
  + bet symmetry                        ── opposing sides of the SAME fixture?
  + stake magnitude                     ── is the matched stake large?
  + stake equality                      ── are the opposing stakes near-equal?
  + timing                              ── were they placed close together?
  + the sweep pattern                   ── deposit -> one big bet -> fast cash-out?

None of these alone is fraud; together they are. The detector never sees the
label — it is scored against it afterwards (precision / recall / F1), and the
honest result is that it clears the legit look-alikes the naive rules drown in.

USAGE
-----
    python3 detect_esoccer_aml.py [--data ./data] [-o blue_team_dashboard.html]

Builds on the Red Team output (users/transactions/bets/fixtures CSVs).
Author: César B. Miranda.  Synthetic data — no real PII.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import networkx as nx
import pandas as pd

# Detection parameters (tuning these is the precision/recall tradeoff).
FLOOR = 300        # min stake to count as a "large" matched bet (clears small household bets)
RATIO_MIN = 0.75   # how near-equal opposing stakes must be
WINDOW_MIN = 180   # minutes between the opposing bets
FLAG_AT = 70       # risk-score threshold to raise an alert (precision-prioritising)


# --------------------------------------------------------------------------- #
# Load
# --------------------------------------------------------------------------- #
def load(data_dir):
    d = Path(data_dir)
    users = pd.read_csv(d / "users.csv")
    txns = pd.read_csv(d / "transactions.csv", parse_dates=["timestamp"])
    bets = pd.read_csv(d / "bets.csv", parse_dates=["timestamp"])
    return users, txns, bets


# --------------------------------------------------------------------------- #
# 1) Identity-linkage graph (networkx): connect accounts sharing IP/device/payout
#    Connected components are candidate rings — and recover the whole ring from
#    any single flagged account.
# --------------------------------------------------------------------------- #
def linkage_clusters(users):
    g = nx.Graph()
    g.add_nodes_from(users["user_id"])
    for attr in ["ip_address", "device_id", "payout_destination"]:
        for _, grp in users.groupby(attr):
            ids = grp["user_id"].tolist()
            for i in range(len(ids) - 1):          # chain the shared-attribute group
                g.add_edge(ids[i], ids[i + 1], via=attr)
    cluster_of, size_of = {}, {}
    for comp in nx.connected_components(g):
        for uid in comp:
            cluster_of[uid] = min(comp)
            size_of[uid] = len(comp)
    return g, cluster_of, size_of


# --------------------------------------------------------------------------- #
# 2) Matched co-bet signal: opposing sides of the same fixture, large + near-equal
#    + close in time. Only large bets are considered (small household bets never
#    enter — magnitude is part of the signal).
# --------------------------------------------------------------------------- #
def matched_cobets(bets):
    big = bets[bets["stake"] >= FLOOR]
    best = {}   # user_id -> dict(stake, ratio, dt, partner)
    for _, grp in big.groupby("match_id"):
        over = grp[grp["selection"] == "over"]
        under = grp[grp["selection"] == "under"]
        if over.empty or under.empty:
            continue
        for o in over.itertuples():
            for u in under.itertuples():
                if o.user_id == u.user_id:
                    continue
                hi, lo = max(o.stake, u.stake), min(o.stake, u.stake)
                ratio = lo / hi
                dt = abs((o.timestamp - u.timestamp).total_seconds()) / 60.0
                if ratio < RATIO_MIN or dt > WINDOW_MIN:
                    continue
                for uid, partner in ((o.user_id, u.user_id), (u.user_id, o.user_id)):
                    cur = best.get(uid)
                    if cur is None or ratio > cur["ratio"] or (
                            ratio == cur["ratio"] and lo > cur["stake"]):
                        best[uid] = {"stake": lo, "ratio": ratio, "dt": dt,
                                     "partner": partner}
    return best


# --------------------------------------------------------------------------- #
# 3) Activity / sweep features per account
# --------------------------------------------------------------------------- #
def activity_features(users, txns, bets):
    NOW = pd.Timestamp("2026-06-24 12:00:00")
    bet_g = bets.groupby("user_id")
    feats = pd.DataFrame({
        "n_bets": bet_g.size(),
        "max_stake": bet_g["stake"].max(),
        "total_stake": bet_g["stake"].sum(),
    }).reindex(users["user_id"]).fillna(0)

    dep = txns[txns["type"] == "deposit"].groupby("user_id")["amount"].sum()
    wd = txns[txns["type"] == "withdrawal"].groupby("user_id")["amount"].sum()
    feats["deposits"] = dep.reindex(users["user_id"]).fillna(0).values
    feats["withdrawals"] = wd.reindex(users["user_id"]).fillna(0).values

    reg = pd.to_datetime(users.set_index("user_id")["registration_date"])
    feats["reg_days_ago"] = (NOW - reg).dt.total_seconds().values / 86400.0
    return feats


# --------------------------------------------------------------------------- #
# 4) Combination risk score (interpretable points; never uses the label)
# --------------------------------------------------------------------------- #
def score_accounts(users, size_of, matched, feats):
    rows = []
    for uid in users["user_id"]:
        f = feats.loc[uid]
        m = matched.get(uid)
        s, signals = 0, []

        if size_of.get(uid, 1) >= 2:
            s += 20
            signals.append("identity-linked")

        if m:
            s += 40
            signals.append("matched co-bet")
            s += 20 if m["stake"] >= 3000 else 12 if m["stake"] >= 1000 else 5
            if m["stake"] >= 1000:
                signals.append("large stake")
            s += 10 if m["ratio"] >= 0.9 else 5
            if m["ratio"] >= 0.9:
                signals.append("near-equal")
            s += 10 if m["dt"] <= 15 else 5 if m["dt"] <= 60 else 0
            if m["dt"] <= 15:
                signals.append("synchronized")

        if f["n_bets"] <= 2 and f["max_stake"] >= 1000:
            s += 15
            signals.append("single large bet")

        if f["reg_days_ago"] <= 7:
            s += 5
            signals.append("new account")

        rows.append({"user_id": uid, "score": s, "signals": ", ".join(signals),
                     "cluster_size": size_of.get(uid, 1),
                     "matched_partner": m["partner"] if m else None})
    return pd.DataFrame(rows).set_index("user_id")


# --------------------------------------------------------------------------- #
# Evaluation helpers
# --------------------------------------------------------------------------- #
def prf(flagged: set, truth: set):
    tp = len(flagged & truth); fp = len(flagged - truth); fn = len(truth - flagged)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f1}


# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #
def ring_svg(users, scored, flagged, truth):
    """Draw one detected ring: two mules, the shared identifier, opposing bets."""
    tp_rings = users[(users["label"] == "fraud_ring") &
                     (users["user_id"].isin(flagged))]
    if tp_rings.empty:
        return "<div style='color:#7C8794'>No ring to display.</div>"
    ring_id = tp_rings["ring_id"].iloc[0]
    mules = users[users["ring_id"] == ring_id].head(2).reset_index(drop=True)
    a, b = mules.iloc[0], mules.iloc[1]
    shared = [x for x in ["ip_address", "device_id", "payout_destination"]
              if a[x] == b[x]]
    shared_lbl = {"ip_address": "IP", "device_id": "device",
                  "payout_destination": "payout"}
    link = " + ".join(shared_lbl[x] for x in shared) if shared else "matched bet only"
    return f"""<svg viewBox="0 0 460 250" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:auto;">
      <line x1="90" y1="70" x2="230" y2="125" stroke="#E5564B" stroke-width="1.5" opacity="0.6"/>
      <line x1="90" y1="180" x2="230" y2="125" stroke="#E5564B" stroke-width="1.5" opacity="0.6"/>
      <line x1="90" y1="70" x2="90" y2="180" stroke="#E2A93B" stroke-width="1.4" stroke-dasharray="5 4" opacity="0.8"/>
      <circle cx="90" cy="70" r="13" fill="#E5564B" stroke="#E6EAEF" stroke-width="1.5"/>
      <circle cx="90" cy="180" r="13" fill="#E5564B" stroke="#E6EAEF" stroke-width="1.5"/>
      <rect x="232" y="110" width="150" height="30" rx="4" fill="#1d242c" stroke="#3FB6C9"/>
      <text x="307" y="129" text-anchor="middle" fill="#3FB6C9" font-family="ui-monospace,monospace" font-size="11">eSoccer fixture</text>
      <text x="90" y="46" text-anchor="middle" fill="#E6EAEF" font-family="ui-monospace,monospace" font-size="10">{a['user_id']}</text>
      <text x="90" y="210" text-anchor="middle" fill="#E6EAEF" font-family="ui-monospace,monospace" font-size="10">{b['user_id']}</text>
      <text x="165" y="88" fill="#9aa3ad" font-family="ui-monospace,monospace" font-size="9">OVER</text>
      <text x="165" y="170" fill="#9aa3ad" font-family="ui-monospace,monospace" font-size="9">UNDER</text>
      <text x="105" y="128" fill="#E2A93B" font-family="ui-monospace,monospace" font-size="9">shared {link}</text>
      <text x="230" y="165" text-anchor="middle" fill="#7C8794" font-family="ui-monospace,monospace" font-size="10">ring {ring_id} recovered</text>
    </svg>"""


def build_dashboard(users, scored, flagged, truth, naive, steps):
    n = len(users)
    combined = prf(flagged, truth)

    # subtype outcomes: how many of each population got flagged (the FP story)
    merged = users.set_index("user_id").join(scored[["score"]])
    merged["flagged"] = merged.index.isin(flagged)
    by_sub = merged.groupby("subtype").agg(total=("score", "size"),
                                           flagged=("flagged", "sum")).sort_values("total", ascending=False)
    sub_rows = ""
    nice = {"normal": "Legit — normal", "household": "Legit — household (look-alike)",
            "budget": "Legit — budget micro-deposit", "vip_fast": "Legit — fast-withdraw VIP",
            "matched_sloppy": "Fraud — sloppy ring", "matched_careful": "Fraud — careful ring",
            "matched_stealth": "Fraud — stealth ring"}
    for sub, row in by_sub.iterrows():
        is_fraud = sub.startswith("matched")
        col = "#E5564B" if is_fraud else "#4FB477"
        verdict = f'{int(row["flagged"])}/{int(row["total"])} flagged'
        sub_rows += (f'<tr><td>{nice.get(sub, sub)}</td>'
                     f'<td class="mono right">{int(row["total"])}</td>'
                     f'<td class="mono right" style="color:{col}">{verdict}</td></tr>')

    # recall by ring sophistication
    soph_rows = ""
    for sub in ["matched_sloppy", "matched_careful", "matched_stealth"]:
        grp = set(users[users["subtype"] == sub]["user_id"])
        if not grp:
            continue
        rec = len(grp & flagged) / len(grp) * 100
        soph_rows += (f'<div class="bar-row"><div class="bar-label">{nice[sub]}'
                      f'<span class="cnt mono">{len(grp & flagged)}/{len(grp)}</span></div>'
                      f'<div class="bar-track"><div class="bar-fill" style="width:{rec:.0f}%"></div></div>'
                      f'<div class="bar-val mono">{rec:.0f}%</div></div>')

    # threshold sweep (precision/recall tradeoff)
    sweep_rows = ""
    for st in steps:
        mark = ' style="background:#10161d;font-weight:600"' if st["thr"] == FLAG_AT else ""
        sweep_rows += (f'<tr{mark}><td class="mono center">{st["thr"]}</td>'
                       f'<td class="mono right">{st["flagged"]}</td>'
                       f'<td class="mono right">{st["precision"]*100:.0f}%</td>'
                       f'<td class="mono right">{st["recall"]*100:.0f}%</td>'
                       f'<td class="mono right f1">{st["f1"]*100:.0f}%</td></tr>')

    # top alerts
    top = scored[scored.index.isin(flagged)].join(
        users.set_index("user_id")[["label", "subtype", "ring_id"]]).sort_values("score", ascending=False).head(12)
    alert_rows = ""
    for uid, r in top.iterrows():
        ok = r["label"] == "fraud_ring"
        tag = ('<span style="color:#E5564B;font-size:10px">CONFIRMED</span>' if ok
               else '<span style="color:#7C8794;font-size:10px">false positive</span>')
        alert_rows += (f'<tr><td class="mono">{uid}</td><td class="mono center">{int(r["score"])}</td>'
                       f'<td class="sig">{r["signals"]}</td>'
                       f'<td class="mono center">{int(r["cluster_size"])}</td><td>{tag}</td></tr>')

    cleared = int(by_sub.loc[[s for s in by_sub.index if not s.startswith("matched")], "total"].sum()
                  - by_sub.loc[[s for s in by_sub.index if not s.startswith("matched")], "flagged"].sum())
    legit_total = int(by_sub.loc[[s for s in by_sub.index if not s.startswith("matched")], "total"].sum())

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>eSoccer AML — Blue Team</title>
<style>
  :root {{ --bg:#0B0E12; --panel:#13181F; --line:#232A33; --ink:#E6EAEF;
    --muted:#7C8794; --cyan:#3FB6C9; --cyan-dim:#1f5a64; --risk:#E5564B;
    --ok:#4FB477; --amber:#E2A93B; }}
  *{{box-sizing:border-box;}}
  body{{margin:0;background:var(--bg);color:var(--ink);line-height:1.45;
    font-family:ui-sans-serif,-apple-system,"Helvetica Neue",Arial,sans-serif;}}
  .mono{{font-family:ui-monospace,"SF Mono",Menlo,monospace;font-variant-numeric:tabular-nums;}}
  .wrap{{max-width:1080px;margin:0 auto;padding:30px 22px 60px;}}
  header{{border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:24px;
    display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:12px;}}
  .title{{font-size:13px;letter-spacing:.26em;text-transform:uppercase;color:var(--muted);}}
  .title b{{color:var(--ink);}} .title .cyan{{color:var(--cyan);}}
  .meta{{text-align:right;font-size:11px;letter-spacing:.12em;color:var(--muted);}}
  .kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:22px;}}
  .kpi{{background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:15px 16px;}}
  .kpi .lab{{font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:9px;}}
  .kpi .num{{font-size:23px;font-weight:600;}} .kpi.ok .num{{color:var(--ok);}} .kpi.cy .num{{color:var(--cyan);}}
  .kpi .num small{{font-size:11px;color:var(--muted);font-weight:400;}}
  .card{{background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:18px;margin-bottom:16px;}}
  .card h2{{font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--cyan);margin:0 0 6px;}}
  .card .sub{{font-size:12px;color:var(--muted);margin:0 0 14px;}}
  table{{width:100%;border-collapse:collapse;font-size:12.5px;}}
  th{{text-align:left;font-size:9.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);
    border-bottom:1px solid var(--line);padding:0 8px 9px 0;}}
  td{{padding:9px 8px 9px 0;border-bottom:1px solid var(--line);}} tr:last-child td{{border-bottom:none;}}
  .right{{text-align:right;}} .center{{text-align:center;}} .f1{{color:var(--cyan);}}
  .sig{{color:var(--muted);font-size:11px;}}
  .grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;}}
  .bar-row{{display:grid;grid-template-columns:1fr 48px;align-items:center;gap:6px 10px;margin-bottom:14px;}}
  .bar-label{{font-size:12.5px;grid-column:1/2;}} .cnt{{color:var(--muted);font-size:11px;margin-left:8px;}}
  .bar-track{{grid-column:1/2;height:6px;background:#1d242c;border-radius:3px;}}
  .bar-fill{{height:100%;background:linear-gradient(90deg,var(--cyan-dim),var(--cyan));border-radius:3px;}}
  .bar-val{{grid-column:2/3;grid-row:1/3;text-align:right;font-size:12.5px;color:var(--amber);}}
  .insight{{background:#171008;border:1px solid #3a2c12;border-radius:4px;padding:14px 16px;
    font-size:13px;color:#E9D8B5;margin-bottom:16px;}} .insight b{{color:var(--amber);}}
  .legend{{display:flex;gap:14px;font-size:11px;color:var(--muted);margin-top:8px;flex-wrap:wrap;}}
  .legend i{{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px;vertical-align:middle;}}
  footer{{margin-top:22px;padding-top:16px;border-top:1px solid var(--line);font-size:11px;color:var(--muted);line-height:1.7;}}
  @media (max-width:760px){{.kpis{{grid-template-columns:repeat(2,1fr);}} .grid{{grid-template-columns:1fr;}}}}
</style></head><body><div class="wrap">
  <header>
    <div class="title"><span class="cyan">&#9670;</span> eSOCCER AML &nbsp;&middot;&nbsp;
      <b>Blue Team — Ring Detection</b></div>
    <div class="meta">NETWORKX + COMBINATION SCORING<br>SYNTHETIC SPORTSBOOK &middot; {n:,} ACCOUNTS</div>
  </header>

  <div class="kpis">
    <div class="kpi cy"><div class="lab">Precision</div><div class="num">{combined["precision"]*100:.0f}%
      <small>vs {naive["precision"]*100:.0f}% naive</small></div></div>
    <div class="kpi cy"><div class="lab">Recall</div><div class="num">{combined["recall"]*100:.0f}%</div></div>
    <div class="kpi"><div class="lab">Alerts raised</div><div class="num">{len(flagged):,}
      <small>/ {len(truth)} fraud</small></div></div>
    <div class="kpi ok"><div class="lab">Legit cleared</div><div class="num">{cleared:,}<small>/ {legit_total:,}</small></div></div>
  </div>

  <div class="insight">
    <b>Two honest limits, not a perfect score.</b> Naive single-signal rules flag
    every shared-IP household and land at <b>~{naive["precision"]*100:.0f}%</b>
    precision. Scoring the full combination lifts that to
    <b>{combined["precision"]*100:.0f}%</b> at <b>{combined["recall"]*100:.0f}%</b>
    recall, clearing <b>{cleared:,} of {legit_total:,}</b> legitimate accounts —
    but it catches the <i>obvious</i> rings and <b>misses the stealth ones</b>
    (small, uneven, slow washes that sit under the threshold). And precision caps
    here: a residual set of legitimate bettors place coincidental large opposing
    co-bets that are behaviourally <i>indistinguishable</i> from washing on
    transaction data alone. Closing either gap costs the other — tighter rules
    miss more stealth, looser rules flood analysts. Real resolution needs context
    behaviour can't see: KYC, source-of-funds, cross-book history.
  </div>

  <div class="grid">
    <div class="card">
      <h2>Who got flagged — fraud vs. the look-alikes</h2>
      <p class="sub">The naive rules drowned in the green rows. This detector clears them.</p>
      <table><thead><tr><th>Population</th><th class="right">Accounts</th><th class="right">Flagged</th></tr></thead>
      <tbody>{sub_rows}</tbody></table>
    </div>
    <div class="card">
      <h2>One recovered ring</h2>
      <p class="sub">Linkage + matched bet reconstruct the pair.</p>
      {ring_svg(users, scored, flagged, truth)}
      <div class="legend"><span><i style="background:#E5564B"></i>flagged mule</span>
        <span><i style="background:#E2A93B"></i>shared identifier</span>
        <span><i style="background:#3FB6C9"></i>opposing bets</span></div>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <h2>Recall by ring tradecraft</h2>
      <p class="sub">Sloppy rings are easy; careful rings (no shared IP) are the test.</p>
      {soph_rows}
    </div>
    <div class="card">
      <h2>Precision / recall vs. threshold</h2>
      <p class="sub">The operating-point tradeoff (row in use: {FLAG_AT}).</p>
      <table><thead><tr><th class="center">Score &ge;</th><th class="right">Flagged</th>
      <th class="right">Prec.</th><th class="right">Recall</th><th class="right">F1</th></tr></thead>
      <tbody>{sweep_rows}</tbody></table>
    </div>
  </div>

  <div class="card">
    <h2>Top alerts</h2>
    <table><thead><tr><th>Account</th><th class="center">Score</th><th>Signals fired</th>
    <th class="center">Cluster</th><th>Status</th></tr></thead>
    <tbody>{alert_rows}</tbody></table>
  </div>

  <footer>
    Generated by <span style="color:var(--cyan-dim)">detect_esoccer_aml.py</span> &middot;
    networkx identity-linkage graph + interpretable combination scoring, evaluated
    against the Red Team's ground-truth labels. No label is used in scoring.
    Synthetic data &mdash; no PII.
  </footer>
</div></body></html>"""


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Blue Team: eSoccer laundering-ring detection")
    ap.add_argument("--data", default="./data")
    ap.add_argument("-o", "--output", default="blue_team_dashboard.html")
    args = ap.parse_args()

    users, txns, bets = load(args.data)
    truth = set(users[users["label"] == "fraud_ring"]["user_id"])

    print("Building identity-linkage graph…")
    g, cluster_of, size_of = linkage_clusters(users)
    print(f"  {g.number_of_nodes():,} nodes · {g.number_of_edges():,} linkage edges")

    print("Scoring the combination…")
    matched = matched_cobets(bets)
    feats = activity_features(users, txns, bets)
    scored = score_accounts(users, size_of, matched, feats)

    flagged = set(scored[scored["score"] >= FLAG_AT].index)
    combined = prf(flagged, truth)

    # naive baseline: "shares an IP with another account"
    ipc = users.groupby("ip_address")["user_id"].transform("count")
    naive_flagged = set(users[ipc > 1]["user_id"])
    naive = prf(naive_flagged, truth)

    # threshold sweep
    steps = []
    for thr in [40, 50, 60, 70, 80]:
        fl = set(scored[scored["score"] >= thr].index)
        steps.append({"thr": thr, "flagged": len(fl), **prf(fl, truth)})

    print(f"\nNaive 'shared IP':  precision {naive['precision']*100:4.1f}%  recall {naive['recall']*100:4.0f}%")
    print(f"Combination (≥{FLAG_AT}): precision {combined['precision']*100:4.1f}%  "
          f"recall {combined['recall']*100:4.0f}%  F1 {combined['f1']*100:4.0f}%  "
          f"(TP={combined['tp']} FP={combined['fp']} FN={combined['fn']})")
    for sub in ["matched_sloppy", "matched_careful", "matched_stealth"]:
        grp = set(users[users["subtype"] == sub]["user_id"])
        print(f"  recall {sub:16}: {len(grp & flagged)}/{len(grp)}")
    print("threshold sweep (precision / recall tradeoff):")
    for st in steps:
        print(f"  score>={st['thr']}: P={st['precision']*100:4.0f}%  "
              f"R={st['recall']*100:4.0f}%  flagged={st['flagged']}")

    html = build_dashboard(users, scored, flagged, truth, naive, steps)
    Path(args.output).write_text(html, encoding="utf-8")
    print(f"Dashboard -> {args.output}")


if __name__ == "__main__":
    main()
