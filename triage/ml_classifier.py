"""Supervised alert-category classifier.

The model is deliberately small and interpretable: TF-IDF converts alert text
to features and Logistic Regression predicts the category. It predicts
categories only; the rule-based scorer remains responsible for risk priority.
"""
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, Tuple

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from .parser import parse_alert

DEFAULT_ALERTS = Path("data/all_alerts.jsonl")
DEFAULT_LABELS = Path("data/all_labels.csv")


def alert_text(parsed: Dict) -> str:
    """Build the text representation used by the classifier."""
    return " ".join(
        str(parsed.get(field) or "")
        for field in ("rule_name", "raw_log", "log_source", "data_source")
    )


def train_category_model(alerts: Iterable[Dict], labels: pd.DataFrame) -> Pipeline:
    """Train a category model from raw alerts and an answer-key DataFrame."""
    label_map = labels.set_index("alert_id")["label_category"].to_dict()
    texts = []
    targets = []
    for raw_alert in alerts:
        alert_id = raw_alert.get("alert_id")
        if alert_id in label_map:
            texts.append(alert_text(parse_alert(raw_alert)))
            targets.append(label_map[alert_id])

    if len(set(targets)) < 2:
        raise ValueError("Category model needs at least two labelled categories")

    model = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)),
        ("classifier", LogisticRegression(
            max_iter=1000, class_weight="balanced", random_state=42
        )),
    ])
    model.fit(texts, targets)
    return model


@lru_cache(maxsize=1)
def default_category_model() -> Pipeline:
    """Train the production model once from the project's labelled dataset."""
    alerts = []
    with DEFAULT_ALERTS.open(encoding="utf-8") as handle:
        import json
        for line in handle:
            if line.strip():
                alerts.append(json.loads(line))
    labels = pd.read_csv(DEFAULT_LABELS)
    return train_category_model(alerts, labels)


def predict_category(model: Pipeline, parsed: Dict) -> Tuple[str, float]:
    """Return the predicted category and its probability."""
    probabilities = model.predict_proba([alert_text(parsed)])[0]
    best_index = probabilities.argmax()
    return (
        str(model.classes_[best_index]),
        float(probabilities[best_index]),
    )
