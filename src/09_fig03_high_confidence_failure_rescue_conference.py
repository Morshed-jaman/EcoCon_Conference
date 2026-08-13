"""Build conference Figure 3 from frozen Step-7 and EcoCon-NOS artifacts."""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
FIGURE_DATA = ROOT / "paper_assets" / "figure_data"
OUTPUT = ROOT / "paper_assets" / "figures" / "conference_selected"
FAMILIES = ["DDoS", "DoS", "Mirai", "Recon", "Spoofing", "BruteForce", "Web"]

# Same visual identity as conference Figure 2.
PROBLEM_COLOR = "#6C8EBF"
NOS_COLOR = "#D55E00"
EDGE = "#30343B"
NOS_EDGE = "#713000"


def read_csv(name: str) -> list[dict[str, str]]:
    with (RESULTS / name).open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def load_and_validate() -> list[dict[str, float | int | str]]:
    confidence = {r["held_out_family"]: r for r in read_csv("loafo_unknown_confidence_summary.csv")}
    rescue = {r["held_out_family"]: r for r in read_csv("ecocon_nos_overconfident_rescue.csv")}
    if set(confidence) != set(FAMILIES) or set(rescue) != set(FAMILIES):
        raise ValueError("Both source artifacts must contain exactly the seven canonical families")

    data: list[dict[str, float | int | str]] = []
    for family in FAMILIES:
        conf = confidence[family]
        rescued = rescue[family]
        unknown_rows = int(conf["unknown_rows"])
        high_rows = int(rescued["high_confidence_unknown_rows"])
        high_rate = float(conf["fraction_maxprob_ge_095"])
        rescue_rate = float(rescued["EcoConNOS_rescue_rate"])
        if round(unknown_rows * high_rate) != high_rows:
            raise ValueError(f"Panel-A denominator/count mismatch for {family}")
        if not 0.0 <= high_rate <= 1.0 or not 0.0 <= rescue_rate < 1.0:
            raise ValueError(f"Out-of-range rate for {family}")
        rescued_rows = round(high_rows * rescue_rate)
        if abs(rescued_rows / high_rows - rescue_rate) > 5e-11:
            raise ValueError(f"Panel-B conditional denominator mismatch for {family}")
        data.append({
            "family": family,
            "unknown_rows": unknown_rows,
            "high_confidence_rows": high_rows,
            "high_confidence_rate": high_rate,
            "ecocon_nos_rescued_high_confidence_rows": rescued_rows,
            "ecocon_nos_high_confidence_rescue_rate": rescue_rate,
        })

    if not data[2]["ecocon_nos_high_confidence_rescue_rate"] < 1.0:
        raise ValueError("Mirai rescue must remain numerically below 100%")
    return data


def save_data(data: list[dict[str, float | int | str]]) -> None:
    FIGURE_DATA.mkdir(parents=True, exist_ok=True)
    fields = [
        "family", "unknown_rows", "high_confidence_rows", "high_confidence_rate",
        "ecocon_nos_rescued_high_confidence_rows", "ecocon_nos_high_confidence_rescue_rate",
    ]
    with (FIGURE_DATA / "fig03_high_confidence_failure_rescue.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in data:
            saved = dict(row)
            saved["high_confidence_rate"] = f'{float(row["high_confidence_rate"]):.10f}'
            saved["ecocon_nos_high_confidence_rescue_rate"] = (
                f'{float(row["ecocon_nos_high_confidence_rescue_rate"]):.10f}'
            )
            writer.writerow(saved)


def add_labels(ax: plt.Axes, bars, values: list[float], color: str) -> None:
    for bar, value in zip(bars, values):
        inside = value > 92
        ax.text(
            value - 2.0 if inside else value + 1.2,
            bar.get_y() + bar.get_height() / 2,
            f"{value:.2f}%",
            ha="right" if inside else "left",
            va="center",
            fontsize=6.8,
            fontweight="bold",
            color="white" if inside else color,
            zorder=5,
        )


def style_axis(ax: plt.Axes) -> None:
    ax.set_xlim(0, 100)
    ax.set_xticks(np.arange(0, 101, 20))
    ax.grid(axis="x", color="#D7DADF", linewidth=0.55, alpha=0.8, zorder=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(direction="out", length=3, width=0.6)


def build_figure(data: list[dict[str, float | int | str]]) -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 8,
        "axes.labelsize": 8,
        "axes.titlesize": 8.5,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "axes.linewidth": 0.7,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "svg.fonttype": "none",
    })

    y = np.arange(len(FAMILIES))
    high = [100 * float(r["high_confidence_rate"]) for r in data]
    rescue = [100 * float(r["ecocon_nos_high_confidence_rescue_rate"]) for r in data]
    fig, (left, right) = plt.subplots(
        1, 2, figsize=(7.1, 3.55), sharey=True, facecolor="white",
        gridspec_kw={"wspace": 0.12},
    )

    bars_a = left.barh(y, high, height=0.62, color=PROBLEM_COLOR, edgecolor=EDGE,
                       linewidth=0.65, zorder=3)
    bars_b = right.barh(y, rescue, height=0.62, color=NOS_COLOR, edgecolor=NOS_EDGE,
                        linewidth=1.0, hatch="xx", zorder=3)
    left.set_yticks(y, FAMILIES)
    left.invert_yaxis()
    left.set_title("(a) High-confidence unseen samples", pad=8)
    right.set_title("(b) EcoCon-NOS rescue of high-confidence unknowns", pad=8)
    left.set_xlabel("Unknown samples with XGBoost confidence ≥ 0.95\n(%)", labelpad=6)
    right.set_xlabel("High-confidence unknowns rejected by EcoCon-NOS\n(%)", labelpad=6)
    style_axis(left)
    style_axis(right)
    right.spines["left"].set_color("#A8ADB5")
    right.tick_params(axis="y", left=False, labelleft=False)
    add_labels(left, bars_a, high, "#314D73")
    add_labels(right, bars_b, rescue, NOS_EDGE)

    fig.text(
        0.5, 0.035,
        "Panel (b) is conditioned on unknown samples with XGBoost confidence ≥ 0.95.",
        ha="center", va="bottom", fontsize=6.7, color="#4F545C",
    )
    fig.subplots_adjust(left=0.115, right=0.985, top=0.88, bottom=0.23)
    stem = OUTPUT / "fig03_high_confidence_failure_rescue"
    fig.savefig(stem.with_suffix(".png"), dpi=600, bbox_inches="tight", pad_inches=0.04,
                facecolor="white")
    fig.savefig(stem.with_suffix(".pdf"), bbox_inches="tight", pad_inches=0.04,
                facecolor="white")
    fig.savefig(stem.with_suffix(".svg"), bbox_inches="tight", pad_inches=0.04,
                facecolor="white")
    plt.close(fig)


def main() -> None:
    data = load_and_validate()
    save_data(data)
    build_figure(data)
    print("Figure 3 validation: PASS")


if __name__ == "__main__":
    main()
