"""
Evaluate the baseline scorer against the labelled answer key.
Reports category accuracy and per-priority precision/recall, and saves a
confusion summary. The agent (Week 4+) will be scored with this same script
so you can show whether the LLM beats the baseline.
"""
import csv
import sys
from collections import defaultdict

import pandas as pd
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

sys.path.insert(0, ".")
from triage.ml_classifier import train_category_model
from triage.pipeline import load_alerts, triage_all


def load_labels(path: str) -> dict:
    return {r["alert_id"]: r for r in csv.DictReader(open(path))}


def precision_recall(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f1


def main(alerts_path="data/all_alerts.jsonl", labels_path="data/all_labels.csv"):
    alerts = load_alerts(alerts_path)
    df = triage_all(alerts)
    labels = load_labels(labels_path)

    cat_correct = 0
    prio_tp = defaultdict(int); prio_fp = defaultdict(int); prio_fn = defaultdict(int)

    for _, row in df.iterrows():
        truth = labels[row["alert_id"]]
        if row["category_guess"] == truth["label_category"]:
            cat_correct += 1
        pred_p, true_p = row["priority"], truth["label_priority"]
        for band in ("Critical", "High", "Medium", "Low"):
            if pred_p == band and true_p == band: prio_tp[band] += 1
            elif pred_p == band and true_p != band: prio_fp[band] += 1
            elif pred_p != band and true_p == band: prio_fn[band] += 1

    print(f"Category accuracy: {cat_correct}/{len(df)} = {cat_correct/len(df):.1%}\n")
    print(f"{'Priority':<10}{'Precision':>10}{'Recall':>10}{'F1':>8}")
    for band in ("Critical", "High", "Medium", "Low"):
        p, r, f1 = precision_recall(prio_tp[band], prio_fp[band], prio_fn[band])
        print(f"{band:<10}{p:>10.2f}{r:>10.2f}{f1:>8.2f}")

    # Recall on serious threats matters most in security
    serious_tp = prio_tp["Critical"] + prio_tp["High"]
    serious_fn = prio_fn["Critical"] + prio_fn["High"]
    sr = serious_tp / (serious_tp + serious_fn) if (serious_tp + serious_fn) else 0
    print(f"\nRecall on High+Critical (catch rate for real threats): {sr:.1%}")

    # Evaluate the supervised model on alerts it did not see during training.
    label_frame = pd.read_csv(labels_path)
    labelled_ids = [a["alert_id"] for a in alerts if a["alert_id"] in labels]
    train_ids, test_ids = train_test_split(
        labelled_ids,
        test_size=0.25,
        random_state=42,
        stratify=[labels[alert_id]["label_category"] for alert_id in labelled_ids],
    )
    train_id_set = set(train_ids)
    test_alerts = [a for a in alerts if a["alert_id"] in set(test_ids)]
    train_alerts = [a for a in alerts if a["alert_id"] in train_id_set]
    ml_model = train_category_model(train_alerts, label_frame)
    ml_df = triage_all(test_alerts, ml_model=ml_model)
    y_true = [labels[alert_id]["label_category"] for alert_id in ml_df["alert_id"]]
    y_pred = ml_df["ml_category"].tolist()
    print("\nSupervised ML category model (held-out test set)")
    print(f"Accuracy: {accuracy_score(y_true, y_pred):.1%}")
    print(classification_report(y_true, y_pred, zero_division=0))


if __name__ == "__main__":
    main()
