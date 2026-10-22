"""Rank where to look for malicious false positives.

Two views, both advisory:

- ``rank_groups``: deterministic FP rate per ``(rule, evidence signature)``.
  This is the honest baseline and needs no dependency.
- ``train``: an optional regularized classifier over the flattened checks.
  It exists to rank unseen findings, never to decide a rule change.

The label set is small (29 hard FPs at the pinned corpus), so training
metrics are in-sample summaries, not efficacy claims. The counterfactual
runner is what accepts a candidate.
"""

from __future__ import annotations

from collections import defaultdict

from ..features.checks import flatten, signature


def _labelled(rows: list[dict], labels: tuple[str, ...]) -> list[dict]:
    return [row for row in rows if row.get("label") in labels]


def rank_groups(
    rows: list[dict],
    min_support: int = 1,
    labels: tuple[str, ...] = ("hard_fp", "tp_benign"),
) -> list[dict]:
    groups: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"fp": 0, "tp_benign": 0, "packages": set()}
    )
    for row in _labelled(rows, labels):
        key = (row.get("rule_id", ""), signature(flatten(row.get("checks"))))
        group = groups[key]
        bucket = "fp" if row["label"] == "hard_fp" else "tp_benign"
        group[bucket] += 1
        group["packages"].add(row.get("package", ""))
    ranked = []
    for (rule, sig), group in groups.items():
        support = group["fp"] + group["tp_benign"]
        if support < min_support:
            continue
        ranked.append(
            {
                "rule_id": rule,
                "signature": sig,
                "support": support,
                "fp": group["fp"],
                "tp_benign": group["tp_benign"],
                "fp_rate": round(group["fp"] / support, 3),
                "packages": sorted(group["packages"]),
            }
        )
    ranked.sort(key=lambda row: (-row["fp"], -row["fp_rate"], -row["support"]))
    return ranked


def rank_by_fingerprint(rows: list[dict], min_support: int = 1) -> dict[str, list[dict]]:
    """The same ranking, sliced by instrument.

    A fingerprint change is a new instrument. Pooling its rows with another
    instrument hides whichever one is noisier.
    """

    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        grouped[row.get("config_fingerprint") or "unknown"].append(row)
    return {
        fingerprint: rank_groups(
            group,
            min_support=min_support,
            labels=("hard_fp", "tp_benign", "weak_fp"),
        )
        for fingerprint, group in grouped.items()
    }


def _features(rows: list[dict]) -> tuple[list[list[float]], list[int], list[str]]:
    names: list[str] = []
    for row in rows:
        for key, value in flatten(row.get("checks")).items():
            name = f"{key}={value}"
            if name not in names:
                names.append(name)
        rule = f"rule={row.get('rule_id', '')}"
        if rule not in names:
            names.append(rule)
    index = {name: position for position, name in enumerate(names)}
    matrix = []
    labels = []
    for row in rows:
        vector = [0.0] * len(names)
        for key, value in flatten(row.get("checks")).items():
            vector[index[f"{key}={value}"]] = 1.0
        vector[index[f"rule={row.get('rule_id', '')}"]] = 1.0
        matrix.append(vector)
        labels.append(1 if row["label"] == "hard_fp" else 0)
    return matrix, labels, names


def train(rows: list[dict]):
    """Fit a regularized logistic model; raise if scikit-learn is absent."""

    try:
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import roc_auc_score
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("install the 'ml' extra to train the ranker") from exc

    data = _labelled(rows, ("hard_fp", "tp_benign"))
    matrix, labels, names = _features(data)
    if len(set(labels)) < 2:
        raise ValueError("need both hard_fp and tp_benign rows to train")
    model = LogisticRegression(
        class_weight="balanced", max_iter=2000, C=0.5, solver="liblinear"
    )
    model.fit(matrix, labels)
    scores = model.predict_proba(matrix)[:, 1]
    weights = sorted(
        zip(names, model.coef_[0]), key=lambda item: -abs(item[1])
    )
    return {
        "model": model,
        "features": names,
        "in_sample_auc": round(float(roc_auc_score(labels, scores)), 3),
        "weights": [
            {"feature": name, "weight": round(float(weight), 3)}
            for name, weight in weights[:20]
        ],
        "note": "in-sample; the corpus is 29 FPs, not an efficacy sample",
    }
