#!/usr/bin/env python3
"""
generate_esoccer_data.py  —  Red Team: synthetic eSoccer sportsbook + injected laundering
==========================================================================================

Part one of the **esoccer-aml-engine**. This builds the "haystack" — a realistic
eSoccer (virtual-football) sportsbook full of chaotic legitimate bettors — and
hides "needles" in it: coordinated matched-betting laundering rings.

The whole point of a Red Team is to make detection HARD and honest. So the
haystack is deliberately seeded with **legitimate look-alikes** that trip naive
rules:

  * CGNAT / household IP sharing  -> "shared IP" is common among innocent users.
  * Legit opposing-bet households  -> two people on one wifi betting opposite
    sides of a match looks like layering, but the stakes are uneven, the timing
    is loose, and there's no clean sweep-and-withdraw.
  * Fast-withdrawing VIPs           -> looks like "stashing".
  * Budget micro-depositors         -> looks like "smurfing".

The injected rings vary in tradecraft — sloppy ones share IP/device/payout and
fire within minutes (easy to catch); careful ones use distinct IPs, staggered
timing, and uneven stakes (the Blue Team should *miss* some of these, which is
the honest part).

Every user carries a ground-truth label so the Blue Team's detection can be
scored with real precision/recall. Output: users.csv, transactions.csv,
bets.csv, fixtures.csv.

USAGE
-----
    python3 generate_esoccer_data.py [--users 5000] [--rings 25]
            [--output-dir ./data] [--seed 7]

Author: César B. Miranda.  Data is 100% synthetic — no real PII.
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

# --------------------------------------------------------------------------- #
# eSoccer environment (mirrors Bet365 / William Hill virtual leagues)
# --------------------------------------------------------------------------- #
LEAGUES = [("eSoccer GT Leagues", 12), ("eSoccer eAdriatic League", 10),
           ("eSoccer H2H GG League", 8), ("eSoccer Battle Volta", 6)]
TEAMS = ["Argentina", "Spain", "Mexico", "France", "Australia", "Paraguay",
         "Netherlands", "USA", "Aston Villa", "Newcastle", "Man City",
         "Real Madrid", "England", "Atletico Madrid", "PSG", "Barcelona",
         "Bayern Munich", "Liverpool", "Inter", "Juventus", "Chelsea", "Arsenal"]
HANDLES = ["Cira", "Cofi111", "Dicca", "cappo", "Vendetta", "Kangal", "Baba",
           "Viper", "HOLLYWOOD", "GRIMACE", "ADEPT", "ENT", "CROWN", "ODYSSEY",
           "Stasyan", "Sheva", "Kai", "Samuel", "Iron", "Cezar", "Boss", "Niko"]

NOW = datetime(2026, 6, 24, 12, 0, 0)     # fixed reference time for reproducibility
WINDOW = 7                                 # days of activity
MARGIN = 0.05                              # sportsbook overround (the vig)

_ids = {"u": 0, "t": 0, "b": 0}


def _nid(kind, prefix, width):
    _ids[kind] += 1
    return f"{prefix}{_ids[kind]:0{width}d}"


def _ts(days_ago=None, base=None, jitter_min=0):
    base = base or (NOW - timedelta(days=random.uniform(0, WINDOW)) if days_ago is None
                    else NOW - timedelta(days=days_ago))
    return base + timedelta(minutes=jitter_min)


# --------------------------------------------------------------------------- #
# Fixtures + 2-way Over/Under market with the vig baked in
# --------------------------------------------------------------------------- #
def build_fixtures(n=80):
    fx = []
    for _ in range(n):
        league, mins = random.choice(LEAGUES)
        a, b = random.sample(TEAMS, 2)
        ha, hb = random.sample(HANDLES, 2)
        p_over = random.uniform(0.35, 0.65)            # true probability
        # overround: implied probs sum to 1 + MARGIN
        odds_over = round(1 / (p_over * (1 + MARGIN)), 2)
        odds_under = round(1 / ((1 - p_over) * (1 + MARGIN)), 2)
        kickoff = NOW - timedelta(days=random.uniform(0, WINDOW))
        fx.append({
            "match_id": _nid("b", "FIX_", 4).replace("BET", "FIX"),
            "league": league, "duration_min": mins,
            "event": f"O/U 2.5 — {a} ({ha}) vs {b} ({hb})",
            "odds_over": odds_over, "odds_under": odds_under,
            "result": "over" if random.random() < p_over else "under",
            "kickoff": kickoff,
        })
    # fix id scheme (avoid clobbering bet counter)
    for i, f in enumerate(fx):
        f["match_id"] = f"FIX_{i:04d}"
    return fx


# --------------------------------------------------------------------------- #
# Shared helpers for records
# --------------------------------------------------------------------------- #
def add_user(users, label, subtype, ip, device, payout, reg, total_dep, ring=None):
    uid = _nid("u", "USR_", 5)
    users.append({"user_id": uid, "label": label, "subtype": subtype,
                  "ring_id": ring, "ip_address": ip, "device_id": device,
                  "payout_destination": payout, "registration_date": reg,
                  "total_deposited": round(total_dep, 2)})
    return uid


def add_deposit(txns, uid, amount, ts, method="card"):
    txns.append({"txn_id": _nid("t", "TXN_", 7), "user_id": uid, "type": "deposit",
                 "amount": round(amount, 2), "timestamp": ts, "method": method,
                 "destination": None})


def add_withdrawal(txns, uid, amount, ts, destination):
    txns.append({"txn_id": _nid("t", "TXN_", 7), "user_id": uid, "type": "withdrawal",
                 "amount": round(amount, 2), "timestamp": ts, "method": "payout",
                 "destination": destination})


def place_bet(bets, fixtures_by_id, uid, fix, selection, stake, ts):
    odds = fix["odds_over"] if selection == "over" else fix["odds_under"]
    win = (selection == fix["result"])
    payout = round(stake * odds, 2) if win else 0.0
    bets.append({"bet_id": _nid("b", "BET_", 7), "user_id": uid,
                 "match_id": fix["match_id"], "market": "O/U 2.5",
                 "selection": selection, "stake": round(stake, 2), "odds": odds,
                 "potential_return": round(stake * odds, 2),
                 "outcome": "win" if win else "lose", "payout": payout,
                 "timestamp": ts})
    return payout


def rand_ip():
    return f"{random.randint(11,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


# --------------------------------------------------------------------------- #
# 1) The haystack: legitimate bettors (chaotic, lose to the vig)
#    A slice of them share CGNAT / household IPs — the first confounder.
# --------------------------------------------------------------------------- #
def gen_legit(users, txns, bets, fixtures, n, shared_ips):
    for _ in range(n):
        total_dep = max(10.0, round(np.random.lognormal(mean=4.2, sigma=0.95), 2))
        # ~8% sit behind a shared IP (mobile carrier CGNAT / family wifi)
        ip = random.choice(shared_ips) if random.random() < 0.08 else rand_ip()
        device = _nid("b", "DEV_", 6).replace("BET", "DEV")
        payout = _nid("b", "PAY_", 6).replace("BET", "PAY")
        reg = NOW - timedelta(days=random.uniform(10, 365))
        uid = add_user(users, "legitimate", "normal", ip, device, payout, reg, total_dep)

        # deposits: 1-4 events over the window
        k = random.randint(1, 4)
        for _ in range(k):
            add_deposit(txns, uid, total_dep / k, _ts())

        # bets: chaotic; stakes a fraction of bankroll; recycle winnings
        balance = total_dep
        for _ in range(random.randint(1, 16)):
            if balance < 5:
                break
            fix = random.choice(fixtures)
            stake = min(balance, random.uniform(5, max(6, total_dep * 0.4)))
            balance -= stake
            balance += place_bet(bets, None, uid, fix, random.choice(["over", "under"]),
                                 stake, fix["kickoff"] - timedelta(minutes=random.uniform(1, 90)))
        # occasional legit cash-out if they ran up a balance
        if balance > total_dep * 1.5 and random.random() < 0.5:
            add_withdrawal(txns, uid, balance * random.uniform(0.4, 0.9),
                           _ts(), payout)


# --------------------------------------------------------------------------- #
# 2) Confounder: legit opposing-bet HOUSEHOLDS (the matched-betting look-alike)
#    Shared IP (+ sometimes device), opposing bets on popular fixtures, but
#    UNEVEN moderate stakes, loose timing, distinct payouts, no clean sweep.
# --------------------------------------------------------------------------- #
def gen_household_pairs(users, txns, bets, fixtures, n_pairs):
    for _ in range(n_pairs):
        ip = rand_ip()
        shared_device = _nid("b", "DEV_", 6).replace("BET", "DEV") if random.random() < 0.4 else None
        reg_base = NOW - timedelta(days=random.uniform(20, 300))
        members = []
        for _ in range(2):
            dep = max(20.0, round(np.random.lognormal(mean=4.3, sigma=0.6), 2))
            device = shared_device or _nid("b", "DEV_", 6).replace("BET", "DEV")
            payout = _nid("b", "PAY_", 6).replace("BET", "PAY")   # separate people -> separate payouts
            uid = add_user(users, "legitimate", "household", ip, device, payout,
                           reg_base + timedelta(days=random.uniform(0, 40)), dep)
            add_deposit(txns, uid, dep, _ts())
            members.append((uid, dep))
        # they bet opposite sides of 1-2 shared fixtures, but sloppily (uneven, loose timing)
        for fix in random.sample(fixtures, random.randint(1, 2)):
            evening = fix["kickoff"] - timedelta(minutes=random.uniform(5, 240))
            s1 = members[0][1] * random.uniform(0.1, 0.45)
            s2 = members[1][1] * random.uniform(0.1, 0.45)        # unequal stakes
            place_bet(bets, None, members[0][0], fix, "over", s1,
                      evening + timedelta(minutes=random.uniform(0, 120)))
            place_bet(bets, None, members[1][0], fix, "under", s2,
                      evening + timedelta(minutes=random.uniform(0, 120)))
        # plus normal individual bets so they look like real users
        for uid, dep in members:
            for _ in range(random.randint(2, 8)):
                fix = random.choice(fixtures)
                place_bet(bets, None, uid, fix, random.choice(["over", "under"]),
                          random.uniform(5, dep * 0.3),
                          fix["kickoff"] - timedelta(minutes=random.uniform(1, 90)))


# --------------------------------------------------------------------------- #
# 3) Light confounders: fast-withdrawers (stashing look-alike) + micro-depositors
#    (smurfing look-alike). Mostly relevant to v2/v3 but seeded now for realism.
# --------------------------------------------------------------------------- #
def gen_fast_withdrawers(users, txns, bets, fixtures, n):
    for _ in range(n):
        dep = round(random.uniform(2000, 12000), 2)
        uid = add_user(users, "legitimate", "vip_fast", rand_ip(),
                       _nid("b", "DEV_", 6).replace("BET", "DEV"),
                       _nid("b", "PAY_", 6).replace("BET", "PAY"),
                       NOW - timedelta(days=random.uniform(15, 200)), dep)
        d_ts = _ts()
        add_deposit(txns, uid, dep, d_ts)
        # they actually BET meaningfully (not a single micro-bet) before cashing out
        bal = dep
        for _ in range(random.randint(3, 9)):
            fix = random.choice(fixtures)
            stake = bal * random.uniform(0.1, 0.3)
            bal -= stake
            bal += place_bet(bets, None, uid, fix, random.choice(["over", "under"]),
                             stake, d_ts + timedelta(hours=random.uniform(1, 60)))
        add_withdrawal(txns, uid, bal * random.uniform(0.6, 0.95),
                       d_ts + timedelta(days=random.uniform(1, 4)),
                       users[-1]["payout_destination"])


def gen_micro_depositors(users, txns, bets, fixtures, n):
    for _ in range(n):
        uid = add_user(users, "legitimate", "budget", rand_ip(),
                       _nid("b", "DEV_", 6).replace("BET", "DEV"),
                       _nid("b", "PAY_", 6).replace("BET", "PAY"),
                       NOW - timedelta(days=random.uniform(10, 250)), 0)
        total = 0
        for _ in range(random.randint(4, 12)):           # many small deposits
            amt = random.uniform(10, 60)
            total += amt
            add_deposit(txns, uid, amt, _ts())
        users[-1]["total_deposited"] = round(total, 2)
        for _ in range(random.randint(3, 14)):           # and they play normally
            fix = random.choice(fixtures)
            place_bet(bets, None, uid, fix, random.choice(["over", "under"]),
                      random.uniform(5, 40),
                      fix["kickoff"] - timedelta(minutes=random.uniform(1, 90)))


# --------------------------------------------------------------------------- #
# 3b) The HARD confounder: legit high-roller arbers. They bet large, near-equal
#     OPPOSING stakes on the same fixtures (bonus arbitrage / hedging) — exactly
#     like matched-betting laundering — EXCEPT they keep their funds in play and
#     never sweep. Only the sweep separates them from a ring.
# --------------------------------------------------------------------------- #
def gen_legit_arbers(users, txns, bets, fixtures, n_pairs):
    for _ in range(n_pairs):
        ip = rand_ip()                                   # a pair on shared wifi
        dev = _nid("b", "DEV_", 6).replace("BET", "DEV") if random.random() < 0.5 else None
        reg = NOW - timedelta(days=random.uniform(30, 300))
        members = []
        for _ in range(2):
            dep = round(random.uniform(3000, 6000), 2)
            uid = add_user(users, "legitimate", "arber", ip,
                           dev or _nid("b", "DEV_", 6).replace("BET", "DEV"),
                           _nid("b", "PAY_", 6).replace("BET", "PAY"), reg, dep)
            add_deposit(txns, uid, dep, _ts())
            members.append((uid, dep))
        # the arbitrage: large near-equal opposing stakes on shared fixtures
        for fix in random.sample(fixtures, random.randint(2, 3)):
            base = random.uniform(1500, min(members[0][1], members[1][1]) * 0.85)
            place_bet(bets, None, members[0][0], fix, "over",
                      base * random.uniform(0.97, 1.03),
                      fix["kickoff"] - timedelta(minutes=random.uniform(2, 40)))
            place_bet(bets, None, members[1][0], fix, "under",
                      base * random.uniform(0.97, 1.03),
                      fix["kickoff"] - timedelta(minutes=random.uniform(2, 40)))
        # they keep playing and only withdraw modestly — NO clean sweep
        for uid, dep in members:
            for _ in range(random.randint(5, 11)):
                fix = random.choice(fixtures)
                place_bet(bets, None, uid, fix, random.choice(["over", "under"]),
                          random.uniform(20, dep * 0.12),
                          fix["kickoff"] - timedelta(minutes=random.uniform(1, 90)))
            if random.random() < 0.5:
                add_withdrawal(txns, uid, dep * random.uniform(0.1, 0.3), _ts(),
                               users[-1]["payout_destination"])


# --------------------------------------------------------------------------- #
# 4) The needles: matched-betting laundering rings (Typology A), varied tradecraft
# --------------------------------------------------------------------------- #
def inject_rings(users, txns, bets, fixtures, n_rings):
    twoway = fixtures
    for r in range(n_rings):
        ring_id = f"RING_{r:03d}"
        roll = random.random()
        soph = "sloppy" if roll < 0.35 else "careful" if roll < 0.70 else "stealth"
        fix = random.choice(twoway)

        if soph == "sloppy":                      # shares everything, fires in minutes
            ip_shared = rand_ip()
            dev_shared = _nid("b", "DEV_", 6).replace("BET", "DEV")
            payout_shared = _nid("b", "PAY_", 6).replace("BET", "PAY")
            reg_spread_h, bet_spread_h, wd_delay_d = 0.25, 0.1, random.uniform(0, 0.05)
            wash, stake_jitter = round(random.uniform(3000, 20000), 2), 0.0
        elif soph == "careful":                   # distinct IP/device, sometimes a payout slip
            ip_shared = dev_shared = None
            payout_shared = (_nid("b", "PAY_", 6).replace("BET", "PAY")
                             if random.random() < 0.5 else None)
            reg_spread_h, bet_spread_h, wd_delay_d = 36, 2.0, random.uniform(1, 2)
            wash, stake_jitter = round(random.uniform(3000, 20000), 2), 0.04
        else:                                     # stealth: shares nothing, small + uneven + slow
            ip_shared = dev_shared = payout_shared = None
            reg_spread_h, bet_spread_h, wd_delay_d = 48, 2.8, random.uniform(1, 3)
            wash, stake_jitter = round(random.uniform(350, 850), 2), 0.16

        reg_base = NOW - timedelta(days=random.uniform(0, WINDOW))
        sides = ["over", "under"]
        mules = []
        for m in range(2):                        # cover both sides of the 2-way market
            ip = ip_shared or rand_ip()
            dev = dev_shared or _nid("b", "DEV_", 6).replace("BET", "DEV")
            payout = payout_shared or _nid("b", "PAY_", 6).replace("BET", "PAY")
            reg = reg_base + timedelta(hours=random.uniform(0, reg_spread_h))
            stake = wash * (1 + random.uniform(-stake_jitter, stake_jitter))
            uid = add_user(users, "fraud_ring", f"matched_{soph}",
                           ip, dev, payout, reg, stake, ring=ring_id)
            add_deposit(txns, uid, stake, reg + timedelta(minutes=random.uniform(1, 20)))
            bet_ts = fix["kickoff"] - timedelta(minutes=random.uniform(1, 30)) \
                + timedelta(hours=random.uniform(0, bet_spread_h))
            payout_amt = place_bet(bets, None, uid, fix, sides[m], stake, bet_ts)
            mules.append((uid, payout, payout_amt, bet_ts))

        # the winning mule sweeps the funds out; the loser is abandoned
        for uid, payout, payout_amt, bet_ts in mules:
            if payout_amt > 0:
                add_withdrawal(txns, uid, payout_amt,
                               bet_ts + timedelta(days=wd_delay_d), payout)


# --------------------------------------------------------------------------- #
# Honesty check: show that naive single-signal rules drown in false positives
# --------------------------------------------------------------------------- #
def naive_rule_report(users_df, bets_df):
    # naive rule 1: "flag anyone who shares an IP with another account"
    ip_counts = users_df.groupby("ip_address")["user_id"].transform("count")
    shared_ip_users = users_df[ip_counts > 1]
    r1_flagged = len(shared_ip_users)
    r1_tp = (shared_ip_users["label"] == "fraud_ring").sum()

    # naive rule 2: "flag accounts that bet opposite sides of the same fixture
    #               while sharing an IP" (no stake/timing/sweep checks)
    merged = bets_df.merge(users_df[["user_id", "ip_address", "label"]], on="user_id")
    flagged = set()
    for (ip, mid), grp in merged.groupby(["ip_address", "match_id"]):
        sides = grp.groupby("selection")["user_id"].apply(set)
        if "over" in sides and "under" in sides and len(grp["user_id"].unique()) > 1:
            flagged.update(grp["user_id"].unique())
    r2_flagged = len(flagged)
    r2_tp = users_df[users_df["user_id"].isin(flagged)]["label"].eq("fraud_ring").sum()

    print("\nNAIVE single-signal rules (why the Blue Team must combine signals):")
    print(f"  Rule 'shares an IP':                flags {r1_flagged:>4} accounts, "
          f"only {r1_tp} are fraud  -> precision {r1_tp/max(r1_flagged,1)*100:4.1f}%")
    print(f"  Rule 'opposing bets + shared IP':   flags {r2_flagged:>4} accounts, "
          f"only {r2_tp} are fraud  -> precision {r2_tp/max(r2_flagged,1)*100:4.1f}%")
    print("  => single signals over-flag innocent households/CGNAT. The detector "
          "must score the COMBINATION (linkage + symmetry + stake + timing + sweep).")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Red Team: synthetic eSoccer sportsbook + laundering")
    ap.add_argument("--users", type=int, default=5000, help="legitimate bettors")
    ap.add_argument("--rings", type=int, default=25, help="matched-betting rings to inject")
    ap.add_argument("--output-dir", default="./data")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)

    fixtures = build_fixtures(80)
    shared_ips = [rand_ip() for _ in range(40)]        # CGNAT / carrier pool

    users, txns, bets = [], [], []
    gen_legit(users, txns, bets, fixtures, args.users, shared_ips)
    gen_household_pairs(users, txns, bets, fixtures, n_pairs=50)
    gen_fast_withdrawers(users, txns, bets, fixtures, n=40)
    gen_micro_depositors(users, txns, bets, fixtures, n=60)
    gen_legit_arbers(users, txns, bets, fixtures, n_pairs=10)
    inject_rings(users, txns, bets, fixtures, args.rings)

    users_df = pd.DataFrame(users)
    txns_df = pd.DataFrame(txns)
    bets_df = pd.DataFrame(bets)
    fix_df = pd.DataFrame(fixtures)

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    users_df.to_csv(out / "users.csv", index=False)
    txns_df.to_csv(out / "transactions.csv", index=False)
    bets_df.to_csv(out / "bets.csv", index=False)
    fix_df.drop(columns=["kickoff"]).to_csv(out / "fixtures.csv", index=False)

    n_fraud = (users_df["label"] == "fraud_ring").sum()
    print(f"Wrote {out}/  ->  users={len(users_df):,}  transactions={len(txns_df):,}  "
          f"bets={len(bets_df):,}  fixtures={len(fix_df)}")
    print(f"\nGround truth:")
    print(f"  fraud-ring accounts : {n_fraud:>4}  ({n_fraud/len(users_df)*100:.2f}% of users)")
    print(users_df["subtype"].value_counts().to_string())
    naive_rule_report(users_df, bets_df)


if __name__ == "__main__":
    main()
