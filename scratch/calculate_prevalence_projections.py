import json

# Observed test set metrics from ML-10 (200,000 samples, 100k benign, 100k malicious)
thresholds = {
    "tau_05": {
        "name": "Default Balanced (tau = 0.500000)",
        "tau": 0.500000,
        "tpr": 0.94149,   # 94,149 / 100,000
        "fpr": 0.07093,   # 7,093 / 100,000
    },
    "tau_1pct": {
        "name": "Target 1% FPR (tau = 0.800395)",
        "tau": 0.800395,
        "tpr": 0.85531,   # 85,531 / 100,000
        "fpr": 0.02235,   # 2,235 / 100,000
    },
    "tau_01pct": {
        "name": "Target 0.1% FPR (tau = 0.966365)",
        "tau": 0.966365,
        "tpr": 0.54675,   # 54,675 / 100,000
        "fpr": 0.00198,   # 198 / 100,000
    }
}

prevalences = [
    (0.50, "50.0% (Test Set Benchmark)"),
    (0.01, "1.0% (High-Threat Ingestion / Suspicious Triage)"),
    (0.001, "0.1% (Standard Corporate Endpoint / Email Gateway)"),
    (0.0001, "0.01% (Enterprise Perimeter / High-Volume Gateway, 1 in 10,000)"),
]

def calc_projected_precision(tpr, fpr, p):
    numerator = tpr * p
    denominator = (tpr * p) + (fpr * (1.0 - p))
    if denominator == 0:
        return 0.0
    return numerator / denominator

def calc_sample_counts_at_volume(volume, p, tpr, fpr):
    mal_count = volume * p
    ben_count = volume * (1.0 - p)
    tp = mal_count * tpr
    fn = mal_count * (1.0 - tpr)
    fp = ben_count * fpr
    tn = ben_count * (1.0 - fpr)
    return tp, fp, fn, tn

print("=" * 110)
print(f"{'Threshold':<25} | {'Prevalence':<12} | {'TPR (Recall)':<12} | {'FPR':<10} | {'Projected Precision':<20} | {'False Alert Ratio (FP:TP)'}")
print("=" * 110)

results = {}

for t_key, t_info in thresholds.items():
    tpr = t_info["tpr"]
    fpr = t_info["fpr"]
    results[t_key] = {"name": t_info["name"], "tau": t_info["tau"], "projections": {}}
    
    for p, p_desc in prevalences:
        prec = calc_projected_precision(tpr, fpr, p)
        # Ratio of false alarms to true detections: FP / TP
        # FP = N*(1-p)*fpr, TP = N*p*tpr -> FP/TP = (fpr*(1-p))/(tpr*p)
        fp_to_tp = ((1.0 - p) * fpr) / (p * tpr) if (p * tpr) > 0 else float('inf')
        
        ratio_str = f"{fp_to_tp:.1f} to 1" if fp_to_tp >= 1.0 else f"1 to {1/fp_to_tp:.1f}"
        print(f"{t_info['name']:<25} | {p*100:<11.2f}% | {tpr*100:<11.3f}% | {fpr*100:<9.3f}% | {prec*100:<19.3f}% | {ratio_str}")
        
        results[t_key]["projections"][str(p)] = {
            "prevalence_pct": p * 100,
            "prevalence_desc": p_desc,
            "projected_precision": prec,
            "projected_precision_pct": prec * 100,
            "fp_to_tp_ratio": fp_to_tp,
        }

print("\n" + "=" * 110)
print("ILLUSTRATIVE VOLUME SIMULATION: 100,000 EXECUTABLES PROCESSED PER DAY")
print("=" * 110)

volume = 100000
for p, p_desc in prevalences:
    print(f"\nScenario: Prevalence = {p*100:.2f}% ({p_desc}) on {volume:,} Daily Files:")
    print(f"  Underlying Population: {int(volume*p):,} Malicious, {int(volume*(1-p)):,} Benign")
    for t_key, t_info in thresholds.items():
        tpr = t_info["tpr"]
        fpr = t_info["fpr"]
        tp, fp, fn, tn = calc_sample_counts_at_volume(volume, p, tpr, fpr)
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        print(f"  [{t_info['name']}]")
        print(f"    Alerts: {int(tp+fp):,} Total | TP (Caught): {tp:,.1f} | FP (False Alarms): {fp:,.1f} | FN (Missed): {fn:,.1f} | Precision: {prec*100:.2f}%")

with open(repo_root / "scratch" / "ml11_prevalence_projections.json", "w") as f:
    json.dump(results, f, indent=2)

print("\nSaved scratch/ml11_prevalence_projections.json successfully.")
