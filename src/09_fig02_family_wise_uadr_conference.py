"""Build conference Figure 2 from frozen EcoCon-NOS result artifacts only."""

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
CAPTIONS = ROOT / "paper_assets" / "captions"

FAMILIES = ["DDoS", "DoS", "Mirai", "Recon", "Spoofing", "BruteForce", "Web"]
METHODS = ["MSP", "Entropy", "EcoConMD", "EcoConNOS"]
DISPLAY = {
    "MSP": "MSP",
    "Entropy": "Entropy",
    "EcoConMD": "EcoCon-MD",
    "EcoConNOS": "EcoCon-NOS",
}
COLORS = {
    "MSP": "#B8BDC7",
    "Entropy": "#6C8EBF",
    "EcoConMD": "#2A9D8F",
    "EcoConNOS": "#D55E00",
}
HATCHES = {"MSP": "", "Entropy": "//", "EcoConMD": "..", "EcoConNOS": "xx"}


def read_csv(name: str) -> list[dict[str, str]]:
    with (RESULTS / name).open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def load_and_validate() -> list[dict[str, float | str]]:
    family_rows = read_csv("ecocon_nos_family_comparison.csv")
    indexed = {row["held_out_family"]: row for row in family_rows}
    if set(indexed) != set(FAMILIES) or len(indexed) != 7:
        raise ValueError("Final family-comparison artifact must contain exactly seven families")

    step8 = {
        (row["held_out_family"], row["method"]): row
        for row in read_csv("step8_family_comparison.csv")
        if row["method"] in {"MSP", "Entropy", "EcoConMD"}
    }
    outer = {
        row["held_out_family"]: row
        for row in read_csv("ecocon_nos_outer_results.csv")
        if row["method"] == "EcoConNOS"
    }
    with (RESULTS / "ecocon_nos_config.json").open(encoding="utf-8-sig") as handle:
        nos_config = json.load(handle)
    if abs(float(nos_config["known_rejection_target"]) - 0.05) > 1e-12:
        raise ValueError("Frozen EcoCon-NOS configuration does not use 5% known rejection")

    output: list[dict[str, float | str]] = []
    for family in FAMILIES:
        source = indexed[family]
        record: dict[str, float | str] = {"family": family}
        for method in METHODS:
            value = float(source[method])
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"Out-of-range UADR for {family}/{method}: {value}")
            record[method] = value

        for method in ("MSP", "Entropy", "EcoConMD"):
            row = step8[(family, method)]
            if abs(float(row["UADR"]) - float(record[method])) > 1e-12:
                raise ValueError(f"Conflicting UADR for {family}/{method}")
            if not 0.04 <= float(row["known_rejection_rate"]) <= 0.06:
                raise ValueError(f"Non-comparable known rejection for {family}/{method}")

        nos = outer[family]
        if abs(float(nos["UADR"]) - float(record["EcoConNOS"])) > 1e-12:
            raise ValueError(f"Conflicting UADR for {family}/EcoConNOS")
        # NOS stores the target in its frozen config; its appended outer-result
        # rows intentionally leave the legacy Step-8 `alpha` column blank.
        if not 0.04 <= float(nos["known_rejection_rate"]) <= 0.06:
            raise ValueError(f"Non-comparable known rejection for {family}/EcoConNOS")
        output.append(record)

    if not float(indexed["DDoS"]["EcoConMD"]) > float(indexed["DDoS"]["EcoConNOS"]):
        raise ValueError("Expected DDoS MD/NOS near-tie ordering was not confirmed")
    if abs(float(indexed["Mirai"]["EcoConNOS"]) - 0.99961) > 1e-12:
        raise ValueError("Mirai NOS value differs from frozen final artifact")
    if not float(indexed["Web"]["Entropy"]) > float(indexed["Web"]["EcoConNOS"]):
        raise ValueError("Expected Web entropy/NOS ordering was not confirmed")
    return output


def save_plot_data(data: list[dict[str, float | str]]) -> None:
    FIGURE_DATA.mkdir(parents=True, exist_ok=True)
    fields = ["family", "msp_uadr", "entropy_uadr", "ecocon_md_uadr", "ecocon_nos_uadr"]
    with (FIGURE_DATA / "fig02_family_wise_uadr.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in data:
            writer.writerow({
                "family": row["family"],
                "msp_uadr": f'{float(row["MSP"]):.10f}',
                "entropy_uadr": f'{float(row["Entropy"]):.10f}',
                "ecocon_md_uadr": f'{float(row["EcoConMD"]):.10f}',
                "ecocon_nos_uadr": f'{float(row["EcoConNOS"]):.10f}',
            })


def build_figure(data: list[dict[str, float | str]]) -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 8,
        "axes.labelsize": 9,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "legend.fontsize": 8,
        "axes.linewidth": 0.7,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "svg.fonttype": "none",
    })

    fig, ax = plt.subplots(figsize=(7.1, 3.55), facecolor="white")
    x = np.arange(len(FAMILIES))
    width = 0.19
    bars: dict[str, object] = {}
    for index, method in enumerate(METHODS):
        values = [100.0 * float(row[method]) for row in data]
        bars[method] = ax.bar(
            x + (index - 1.5) * width,
            values,
            width,
            label=DISPLAY[method],
            color=COLORS[method],
            edgecolor="#30343B" if method != "EcoConNOS" else "#713000",
            linewidth=0.65 if method != "EcoConNOS" else 1.0,
            hatch=HATCHES[method],
            zorder=3,
        )

    ax.set_ylim(0, 100)
    ax.set_yticks(np.arange(0, 101, 20))
    ax.set_ylabel("UADR (%)")
    ax.set_xlabel("Held-Out Attack Family", labelpad=5)
    ax.set_xticks(x, FAMILIES)
    ax.grid(axis="y", color="#D7DADF", linewidth=0.55, alpha=0.8, zorder=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(direction="out", length=3, width=0.6)
    ax.legend(
        ncol=4,
        loc="lower center",
        bbox_to_anchor=(0.5, 1.005),
        frameon=False,
        columnspacing=1.6,
        handlelength=1.8,
    )

    # Label proposed-method bars and the MD bars needed for direct interpretation.
    for rect, row in zip(bars["EcoConNOS"], data):
        value = 100.0 * float(row["EcoConNOS"])
        if row["family"] == "DDoS":
            continue  # The near-tie annotation below contains the exact NOS value.
        inside = row["family"] == "Mirai"
        ax.text(rect.get_x() + rect.get_width() / 2, value - 2.0 if inside else value + 1.3,
                f"{value:.2f}", ha="center", va="top" if inside else "bottom",
                fontsize=5.3 if inside else 6.7,
                color="white" if inside else "#713000", fontweight="bold", zorder=5)
    for rect, row in zip(bars["EcoConMD"], data):
        value = 100.0 * float(row["EcoConMD"])
        if row["family"] in {"Mirai", "Recon", "BruteForce", "Web"}:
            ax.text(rect.get_x() + rect.get_width() / 2, value + 1.1, f"{value:.2f}",
                    ha="center", va="bottom", fontsize=6.3, color="#185F57")

    ax.text(0.985, 0.955, "EcoCon-NOS improves over EcoCon-MD on 6/7 folds",
            transform=ax.transAxes, ha="right", va="top", fontsize=7.2, color="#30343B")
    ax.annotate("MD: 55.99%\nNOS: 55.65%",
                xy=(x[0] + 0.5 * width, 55.8), xytext=(x[0] - 0.72, 70),
                fontsize=6.8, color="#3F444B", ha="left", va="center",
                arrowprops={"arrowstyle": "-", "color": "#6B7078", "lw": 0.6})
    ax.annotate("Web remains difficult",
                xy=(x[6] + 1.5 * width, 18.6086), xytext=(x[5] + 0.72, 34),
                fontsize=6.8, color="#4F545C", ha="left",
                arrowprops={"arrowstyle": "-", "color": "#6B7078", "lw": 0.6})
    ax.text(0.5, -0.23,
            "All methods evaluated at approximately 5% known-traffic rejection (α = 0.05).",
            transform=ax.transAxes, ha="center", va="top", fontsize=7, color="#4F545C")

    fig.subplots_adjust(left=0.085, right=0.995, top=0.86, bottom=0.24)
    stem = OUTPUT / "fig02_family_wise_uadr"
    fig.savefig(stem.with_suffix(".png"), dpi=600, bbox_inches="tight", facecolor="white")
    fig.savefig(stem.with_suffix(".pdf"), bbox_inches="tight", facecolor="white")
    fig.savefig(stem.with_suffix(".svg"), bbox_inches="tight", facecolor="white")
    plt.close(fig)


def main() -> None:
    data = load_and_validate()
    save_plot_data(data)
    build_figure(data)
    print("Figure 2 validation: PASS")


if __name__ == "__main__":
    main()
