"""Build conference Figure 4 from frozen Step-6 feature-budget artifacts."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
FIGURE_DATA = ROOT / "paper_assets" / "figure_data"
OUTPUT = ROOT / "paper_assets" / "figures" / "conference_selected"
BUDGETS = [5, 10, 15, 20, 30, 39]

# Conference visual identity shared with Figures 2 and 3.
NEUTRAL = "#6C8EBF"
TEST_COLOR = "#2A9D8F"
SELECTED = "#D55E00"
EDGE = "#30343B"
SELECTED_EDGE = "#713000"


def csv_rows(name: str) -> list[dict[str, str]]:
    with (RESULTS / name).open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def load_and_validate() -> tuple[list[dict[str, float | int | bool]], dict[str, float | int]]:
    dev = {int(r["feature_count"]): float(r["macro_f1"]) for r in csv_rows("feature_budget_dev_metrics.csv")}
    test = {int(r["feature_count"]): float(r["macro_f1"]) for r in csv_rows("feature_budget_test_metrics.csv")}
    with (RESULTS / "feature_budget_selection.json").open(encoding="utf-8-sig") as handle:
        selection = json.load(handle)
    with (RESULTS / "step6_config.json").open(encoding="utf-8-sig") as handle:
        config = json.load(handle)

    epsilon = float(selection["epsilon"])
    full = int(selection["reference_budget"])
    selected = int(selection["selected_budget"])
    threshold = float(selection["eligibility_threshold"])
    precise_dev = {int(k): float(v) for k, v in selection["all_budget_dev_macro_f1"].items()}
    if set(dev) != set(BUDGETS) or set(test) != set(BUDGETS):
        raise ValueError("Development and test artifacts must contain exactly the six predefined budgets")
    if full != 39 or selected != 30 or epsilon != 0.005:
        raise ValueError("Frozen full budget, selected budget, or epsilon differs from the declared protocol")
    if bool(selection["test_loaded"]) or bool(config["test_used_for_selection"]):
        raise ValueError("Test data must not be used for feature-budget selection")
    if bool(config["calibration_used"]):
        raise ValueError("Calibration must not be used for feature-budget selection")
    for budget in BUDGETS:
        if abs(dev[budget] - precise_dev[budget]) > 5e-10:
            raise ValueError(f"Development artifact disagreement at budget {budget}")
    if abs(threshold - (precise_dev[full] - epsilon)) > 1e-15:
        raise ValueError("Saved eligibility threshold does not equal full development score minus epsilon")

    eligible = {b: precise_dev[b] >= threshold for b in BUDGETS}
    if not eligible[30] or eligible[20] or min(b for b in BUDGETS if eligible[b]) != 30:
        raise ValueError("Eligibility rule does not uniquely select 30 as the smallest eligible budget")
    feature_reduction = (full - selected) / full
    test_delta = test[selected] - test[full]
    if abs(feature_reduction - 9 / 39) > 1e-15:
        raise ValueError("Unexpected feature-reduction calculation")
    if not test[selected] < test[full] or abs(test_delta - (-0.0026195217)) > 2e-10:
        raise ValueError("Unexpected official-test comparison")

    data = [{
        "n_features": b,
        "dev_macro_f1": precise_dev[b],
        "test_macro_f1": test[b],
        "eligible_under_epsilon": eligible[b],
        "selected_budget": b == selected,
    } for b in BUDGETS]
    meta = {
        "epsilon": epsilon, "full": full, "selected": selected, "threshold": threshold,
        "feature_reduction": feature_reduction, "test_delta": test_delta,
    }
    return data, meta


def save_data(data: list[dict[str, float | int | bool]]) -> None:
    FIGURE_DATA.mkdir(parents=True, exist_ok=True)
    fields = ["n_features", "dev_macro_f1", "test_macro_f1", "eligible_under_epsilon", "selected_budget"]
    with (FIGURE_DATA / "fig04_feature_budget.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in data:
            saved = dict(row)
            saved["dev_macro_f1"] = f'{float(row["dev_macro_f1"]):.16f}'
            saved["test_macro_f1"] = f'{float(row["test_macro_f1"]):.10f}'
            saved["eligible_under_epsilon"] = str(bool(row["eligible_under_epsilon"])).lower()
            saved["selected_budget"] = str(bool(row["selected_budget"])).lower()
            writer.writerow(saved)


def style_axis(ax: plt.Axes) -> None:
    ax.set_xlim(3, 41)
    ax.set_xticks(BUDGETS)
    ax.set_ylim(0.55, 0.80)
    ax.set_yticks(np.arange(0.55, 0.801, 0.05))
    ax.grid(axis="y", color="#D7DADF", linewidth=0.55, alpha=0.8, zorder=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(direction="out", length=3, width=0.6)
    ax.set_xlabel("Number of Input Features", labelpad=5)


def build_figure(data: list[dict[str, float | int | bool]], meta: dict[str, float | int]) -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 8, "axes.labelsize": 9,
        "axes.titlesize": 8.5, "xtick.labelsize": 8, "ytick.labelsize": 8,
        "axes.linewidth": 0.7, "pdf.fonttype": 42, "ps.fonttype": 42, "svg.fonttype": "none",
    })
    x = np.array(BUDGETS)
    dev = np.array([float(r["dev_macro_f1"]) for r in data])
    test = np.array([float(r["test_macro_f1"]) for r in data])
    selected_index = BUDGETS.index(int(meta["selected"]))
    full_index = BUDGETS.index(int(meta["full"]))

    fig, (left, right) = plt.subplots(1, 2, figsize=(7.1, 3.35), sharey=True,
                                      facecolor="white", gridspec_kw={"wspace": 0.12})
    left.plot(x, dev, color=NEUTRAL, marker="o", markersize=4.7, linewidth=1.45,
              markeredgecolor=EDGE, markeredgewidth=0.65, zorder=3)
    right.plot(x, test, color=TEST_COLOR, marker="o", markersize=4.7, linewidth=1.45,
               markeredgecolor=EDGE, markeredgewidth=0.65, zorder=3)
    for ax in (left, right):
        style_axis(ax)
    left.set_ylabel("Macro-F1")
    left.set_title("(a) Development-time budget selection", pad=8)
    right.set_title("(b) Official-test Macro-F1", pad=8)

    threshold = float(meta["threshold"])
    left.axhline(threshold, color="#696E76", linestyle="--", linewidth=0.9, zorder=1)
    left.text(4.0, threshold + 0.006, "Eligibility threshold (ε = 0.005)",
              fontsize=6.7, color="#4F545C", ha="left", va="bottom")
    left.scatter([30], [dev[selected_index]], s=68, color=SELECTED, edgecolor=SELECTED_EDGE,
                 linewidth=1.0, marker="o", zorder=5)
    left.scatter([39], [dev[full_index]], s=52, facecolor="white", edgecolor=EDGE,
                 linewidth=1.0, marker="s", zorder=5)
    left.annotate("Selected: 30 features", xy=(30, dev[selected_index]), xytext=(21.0, 0.786),
                  fontsize=6.8, color=SELECTED_EDGE, ha="left",
                  arrowprops={"arrowstyle": "-", "color": SELECTED_EDGE, "lw": 0.65})
    left.annotate("Full: 39", xy=(39, dev[full_index]), xytext=(34.4, 0.742),
                  fontsize=6.7, color="#3F444B", ha="left",
                  arrowprops={"arrowstyle": "-", "color": "#6B7078", "lw": 0.6})

    right.scatter([30], [test[selected_index]], s=68, color=SELECTED, edgecolor=SELECTED_EDGE,
                  linewidth=1.0, marker="o", zorder=5)
    right.scatter([39], [test[full_index]], s=52, facecolor="white", edgecolor=EDGE,
                  linewidth=1.0, marker="s", zorder=5)
    right.annotate(f"30: {test[selected_index]:.4f}", xy=(30, test[selected_index]),
                   xytext=(20.5, 0.781), fontsize=6.8, color=SELECTED_EDGE,
                   arrowprops={"arrowstyle": "-", "color": SELECTED_EDGE, "lw": 0.65})
    right.annotate(f"39: {test[full_index]:.4f}", xy=(39, test[full_index]),
                   xytext=(34.0, 0.741), fontsize=6.7, color="#3F444B",
                   arrowprops={"arrowstyle": "-", "color": "#6B7078", "lw": 0.6})
    right.text(0.04, 0.38,
               f'{100 * float(meta["feature_reduction"]):.2f}% fewer input features\n'
               f'Absolute Macro-F1 change = {float(meta["test_delta"]):.5f}',
               transform=right.transAxes, fontsize=6.9, color="#4F545C", ha="left", va="top",
               bbox={"facecolor": "white", "edgecolor": "#C4C8CE", "linewidth": 0.5, "pad": 2.0})

    fig.text(0.5, 0.025, "Budget selected on internal development data; official test used only for final reporting.",
             ha="center", va="bottom", fontsize=6.7, color="#4F545C")
    fig.subplots_adjust(left=0.09, right=0.985, top=0.88, bottom=0.22)
    stem = OUTPUT / "fig04_feature_budget"
    fig.savefig(stem.with_suffix(".png"), dpi=600, bbox_inches="tight", pad_inches=0.04, facecolor="white")
    fig.savefig(stem.with_suffix(".pdf"), bbox_inches="tight", pad_inches=0.04, facecolor="white")
    fig.savefig(stem.with_suffix(".svg"), bbox_inches="tight", pad_inches=0.04, facecolor="white")
    plt.close(fig)


def main() -> None:
    data, meta = load_and_validate()
    save_data(data)
    build_figure(data, meta)
    print("Figure 4 validation: PASS")


if __name__ == "__main__":
    main()
