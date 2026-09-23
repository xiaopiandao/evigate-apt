#!/usr/bin/env python3
"""Build publication figures and machine-readable source data for EviGate-APT.

All drawing, previewing, and exports are performed with Python/matplotlib.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

import matplotlib as mpl

mpl.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from run_stage_b_feature_ablation import fit_logistic  # noqa: E402
from run_stage_b_shortcut_audit import (  # noqa: E402
    shortcut_configurations,
    training_data_for_ids,
)
from run_stage_b_typed_ranker import (  # noqa: E402
    extract_case,
    feature_names,
    load_jsonl,
    membership,
)


CASE_ID = "case_37947035589a61186702"
RULES = ("confidence", "controller", "integrity", "dual")
RULE_LABELS = {
    "confidence": "Confidence",
    "controller": "Controller",
    "integrity": "Integrity",
    "dual": "Dual",
}
RULE_COLORS = {
    "confidence": "#0072B2",
    "controller": "#E69F00",
    "integrity": "#009E73",
    "dual": "#CC79A7",
}


def configure_style() -> None:
    mpl.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": ["Arial", "DejaVu Sans"],
            "font.size": 7.0,
            "axes.labelsize": 7.0,
            "axes.titlesize": 7.5,
            "xtick.labelsize": 6.5,
            "ytick.labelsize": 6.5,
            "legend.fontsize": 6.3,
            "axes.linewidth": 0.7,
            "lines.linewidth": 1.25,
            "svg.fonttype": "none",
            "svg.hashsalt": "evigate-apt-2026-09-15",
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "savefig.facecolor": "white",
            "figure.facecolor": "white",
        }
    )


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    material = list(rows)
    if not material:
        raise ValueError(f"no rows for {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(material[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(material)


def save_figure(fig: plt.Figure, stem: Path) -> None:
    stem.parent.mkdir(parents=True, exist_ok=True)
    creator = "EviGate-APT build_stage4_figures.py"
    fixed_date = datetime(2026, 9, 15, tzinfo=timezone.utc)
    fig.savefig(
        stem.with_suffix(".svg"),
        metadata={"Creator": creator, "Date": "2026-09-15", "Title": stem.name},
        bbox_inches="tight",
        pad_inches=0.03,
    )
    fig.savefig(
        stem.with_suffix(".pdf"),
        metadata={
            "Creator": creator,
            "CreationDate": fixed_date,
            "ModDate": fixed_date,
            "Title": stem.name,
        },
        bbox_inches="tight",
        pad_inches=0.03,
    )
    fig.savefig(
        stem.with_suffix(".png"),
        dpi=300,
        metadata={"Software": creator, "Creation Time": "2026-09-15"},
        bbox_inches="tight",
        pad_inches=0.03,
    )
    fig.savefig(
        stem.with_suffix(".tiff"),
        dpi=600,
        pil_kwargs={"compression": "tiff_lzw"},
        bbox_inches="tight",
        pad_inches=0.03,
    )
    plt.close(fig)


def panel_label(ax: plt.Axes, label: str, x: float = -0.10, y: float = 1.04) -> None:
    ax.text(
        x,
        y,
        label,
        transform=ax.transAxes,
        ha="left",
        va="bottom",
        fontsize=8.5,
        fontweight="bold",
    )


def clean_axes(ax: plt.Axes) -> None:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(length=2.5, width=0.6)
    ax.grid(axis="y", color="#D9D9D9", linewidth=0.45, alpha=0.65, zorder=0)


def rounded_box(
    ax: plt.Axes,
    xy: tuple[float, float],
    width: float,
    height: float,
    title: str,
    body: str,
    *,
    facecolor: str = "#F4F7FA",
    edgecolor: str = "#4D5966",
    linestyle: str = "-",
    title_color: str = "#17365D",
    title_size: float = 6.8,
    body_size: float = 6.0,
) -> FancyBboxPatch:
    x, y = xy
    patch = FancyBboxPatch(
        (x, y),
        width,
        height,
        boxstyle="round,pad=0.008,rounding_size=0.012",
        linewidth=0.8,
        edgecolor=edgecolor,
        facecolor=facecolor,
        linestyle=linestyle,
        transform=ax.transAxes,
        clip_on=False,
    )
    ax.add_patch(patch)
    ax.text(
        x + 0.012,
        y + height - 0.025,
        title,
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=title_size,
        fontweight="bold",
        color=title_color,
    )
    ax.text(
        x + 0.012,
        y + height - 0.070,
        body,
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=body_size,
        color="#263238",
        linespacing=1.25,
    )
    return patch


def arrow(
    ax: plt.Axes,
    start: tuple[float, float],
    end: tuple[float, float],
    *,
    color: str = "#566573",
    linestyle: str = "-",
    mutation_scale: float = 8.0,
) -> None:
    ax.add_patch(
        FancyArrowPatch(
            start,
            end,
            arrowstyle="-|>",
            mutation_scale=mutation_scale,
            linewidth=0.8,
            color=color,
            linestyle=linestyle,
            transform=ax.transAxes,
            clip_on=False,
        )
    )


def _build_figure1_legacy(output_dir: Path, source_dir: Path) -> None:
    # Figure contract: show how proposal locking, certificate verification,
    # cross-view binding, posterior margin, and temporal admissibility form
    # separate assurance obligations before an attributed label is issued.
    # Archetype: schematic-led composite; exports: editable SVG/PDF plus PNG/TIFF.
    fig, ax = plt.subplots(figsize=(7.2, 4.6))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.text(0.015, 0.965, "Inference path", ha="left", va="top", fontsize=7.5, fontweight="bold")

    rounded_box(
        ax,
        (0.02, 0.72),
        0.125,
        0.17,
        "Network window",
        "Packet/flow\naggregates\nNo host-log input",
        facecolor="#EAF3F8",
        title_size=5.9,
    )
    rounded_box(
        ax,
        (0.175, 0.72),
        0.115,
        0.17,
        "Stage A: alert",
        "Lightweight\nnetwork alert\ngeneration",
        facecolor="#E8F1FA",
    )
    rounded_box(
        ax,
        (0.32, 0.72),
        0.15,
        0.17,
        "Candidate graph",
        "±5-min provenance\ngraph opened after\nalert; temporal only",
        facecolor="#F0F7EE",
    )
    rounded_box(
        ax,
        (0.50, 0.72),
        0.13,
        0.17,
        "Stage B",
        "Typed process\nretrieval; ranked\nprocess list",
        facecolor="#EEF6E9",
        body_size=5.2,
    )
    rounded_box(
        ax,
        (0.66, 0.72),
        0.15,
        0.17,
        "Stage C proposal",
        "Five-class posterior\nProposed tactic\nSelector scores",
        facecolor="#F8F0F6",
    )
    rounded_box(
        ax,
        (0.84, 0.72),
        0.14,
        0.17,
        "Conventional path",
        "Confidence / margin\nIntegrity / dual\nIssue or withhold",
        facecolor="#F4F1F8",
        title_size=5.9,
        body_size=5.2,
    )
    arrow(ax, (0.145, 0.805), (0.175, 0.805))
    arrow(ax, (0.290, 0.805), (0.320, 0.805))
    arrow(ax, (0.470, 0.805), (0.500, 0.805))
    arrow(ax, (0.630, 0.805), (0.660, 0.805))
    arrow(ax, (0.810, 0.805), (0.840, 0.805))

    rounded_box(
        ax,
        (0.175, 0.525),
        0.115,
        0.12,
        "No alert",
        "Stop; counted as\nend-to-end miss",
        facecolor="#F3F3F3",
        edgecolor="#8A8A8A",
        title_color="#555555",
        body_size=5.2,
    )
    arrow(ax, (0.232, 0.72), (0.232, 0.645), color="#7A7A7A")

    ax.text(0.32, 0.635, "Proposal-locked evidence path", transform=ax.transAxes, ha="left", va="top", fontsize=6.8, fontweight="bold", color="#17365D")
    rounded_box(
        ax,
        (0.32, 0.38),
        0.15,
        0.18,
        "Evidence package",
        "Ranked processes\nOpaque anchor IDs\nStage-C proposal",
        facecolor="#EEF6E9",
        title_size=5.8,
        body_size=5.2,
    )
    rounded_box(
        ax,
        (0.50, 0.38),
        0.13,
        0.18,
        "LLM auditor",
        "Proposal locked\nSelect one process\nCite owned anchors",
        facecolor="#F8F0F6",
        body_size=5.2,
    )
    rounded_box(
        ax,
        (0.66, 0.38),
        0.15,
        0.18,
        "Certificate verifier",
        "Schema + ownership\nNullable consistency\nMissing-evidence alarm",
        facecolor="#FCEFD8",
        edgecolor="#B36B00",
        body_size=5.0,
    )
    rounded_box(
        ax,
        (0.84, 0.38),
        0.14,
        0.18,
        "BindGate",
        "Pair compatibility\nMargin + time check\nPost-freeze exploratory",
        facecolor="#FFF8E8",
        edgecolor="#B36B00",
        linestyle="--",
        body_size=4.9,
    )
    arrow(ax, (0.395, 0.72), (0.395, 0.56), color="#5C7A52")
    arrow(ax, (0.735, 0.72), (0.565, 0.56), color="#8064A2")
    arrow(ax, (0.470, 0.47), (0.50, 0.47))
    arrow(ax, (0.630, 0.47), (0.66, 0.47))
    arrow(ax, (0.810, 0.47), (0.84, 0.47), color="#B36B00", linestyle="--")

    rounded_box(
        ax,
        (0.47, 0.10),
        0.51,
        0.17,
        "Analyst-facing outcome",
        "Attributed: label + certificate  |  Unattributed: reason\nSeparate integrity / context alarm",
        facecolor="#F4F7FA",
        body_size=5.0,
    )
    arrow(ax, (0.91, 0.38), (0.91, 0.27), color="#B36B00", linestyle="--")

    rounded_box(
        ax,
        (0.02, 0.10),
        0.41,
        0.17,
        "Evaluation sidecar (not an inference input)",
        "Group splits  |  malicious-process IDs\nDerived tactic labels  |  metrics",
        facecolor="#FAFAFA",
        edgecolor="#8C8C8C",
        linestyle="--",
        title_color="#555555",
        body_size=5.4,
    )
    ax.text(0.02, 0.025, "Dashed binding cascade is post-freeze; the sidecar is evaluation-only. No packet-to-process causal edge is asserted.", transform=ax.transAxes, ha="left", va="bottom", fontsize=5.5, color="#555555")
    save_figure(fig, output_dir / "figure1_pipeline_evidence_boundary")

    source = {
        "figure": 1,
        "inference_inputs": ["observed network window", "alert-opened provenance candidate graph"],
        "inference_outputs": ["network alert/no alert", "ranked process candidates", "conditional tactic label/withhold", "evidence certificate", "integrity or context alarm"],
        "llm_path": ["evidence package", "proposal-locked LLM support auditor", "deterministic verifier", "exploratory BindGate cascade"],
        "evaluation_only": ["attack-group splits", "malicious-process IDs", "derived tactic label"],
        "non_claim": "Temporal association is not a traffic-to-process causal edge.",
    }
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "figure1_source.json").write_text(json.dumps(source, indent=2) + "\n", encoding="utf-8")


def build_figure1(output_dir: Path, source_dir: Path) -> None:
    """Build the reviewer-facing four-stage framework diagram."""

    from build_ieee_framework_figure import (
        build_framework,
        configure_style as configure_framework_style,
    )

    # Isolate the framework typography so the legacy supplemental plots retain
    # their own style when the complete five-figure build is requested.
    with mpl.rc_context():
        configure_framework_style()
        fig, source = build_framework()
        save_figure(fig, output_dir / "figure1_pipeline_evidence_boundary")
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "figure1_source.json").write_text(
        json.dumps(source, indent=2) + "\n", encoding="utf-8"
    )


def build_figure2(root: Path, output_dir: Path, source_dir: Path) -> None:
    risk_rows = read_csv(root / "data/derived/stage4_revision/diagnostics/stage4_risk_coverage.csv")
    event_rows = read_csv(root / "data/derived/stage4_revision/diagnostics/stage4_event_accounting.csv")
    bind_rows = read_csv(
        root
        / "data/derived/evigate_llm/v7_bindgate/evaluation_temporal/evigate_bindgate.per_case.csv"
    )

    fig = plt.figure(figsize=(7.2, 3.45))
    gs = fig.add_gridspec(1, 2, width_ratios=(1.35, 1.0), wspace=0.32, left=0.075, right=0.985, bottom=0.18, top=0.93)
    ax1 = fig.add_subplot(gs[0, 0])
    ax2 = fig.add_subplot(gs[0, 1])

    for rule in RULES:
        rows = sorted((r for r in risk_rows if r["rule"] == rule), key=lambda r: float(r["realized_coverage"]))
        x = np.asarray([float(r["realized_coverage"]) for r in rows])
        y = np.asarray([float(r["risk"]) for r in rows])
        lo = np.asarray([float(r["cluster_bootstrap_ci95_lower"]) for r in rows])
        hi = np.asarray([float(r["cluster_bootstrap_ci95_upper"]) for r in rows])
        ax1.fill_between(x, lo, hi, color=RULE_COLORS[rule], alpha=0.09, linewidth=0)
        ax1.plot(x, y, marker="o", markersize=2.8, color=RULE_COLORS[rule], label=RULE_LABELS[rule], zorder=3)
    fixed = 42 / 53
    ax1.axvline(fixed, color="#555555", linestyle="--", linewidth=0.8)
    ax1.text(fixed - 0.012, 0.965, "42/53", rotation=90, ha="right", va="top", fontsize=5.8, color="#555555")
    ax1.set(xlim=(0.07, 1.015), ylim=(-0.015, 1.02), xlabel="Realized coverage", ylabel="Selective labeling risk")
    ax1.set_xticks(np.arange(0.2, 1.01, 0.2))
    ax1.legend(loc="upper left", ncol=2, frameon=False, handlelength=1.5, columnspacing=0.8)
    clean_axes(ax1)
    panel_label(ax1, "a")
    ax1.text(0.98, 0.02, "n = 53; event-cluster bootstrap, 10,000 iterations", transform=ax1.transAxes, ha="right", va="bottom", fontsize=5.3, color="#555555")

    stage_a_alerted = {row["case_id"]: bool(int(row["stage_a_alerted"])) for row in event_rows}
    clean_bind_rows = [row for row in bind_rows if row["condition"] == "clean"]
    if len(clean_bind_rows) != 51:
        raise ValueError(f"expected 51 clean BindGate rows, found {len(clean_bind_rows)}")
    counts = {
        "Correct label": 0,
        "Wrong label": 0,
        "Unattributed after alert": 0,
        "Stage-A miss": 0,
    }
    for row in clean_bind_rows:
        if not stage_a_alerted[row["case_id"]]:
            counts["Stage-A miss"] += 1
        elif row["cascade_attributed"] != "True":
            counts["Unattributed after alert"] += 1
        elif row["cascade_correct"] == "True":
            counts["Correct label"] += 1
        else:
            counts["Wrong label"] += 1
    expected_counts = {
        "Correct label": 18,
        "Wrong label": 6,
        "Unattributed after alert": 12,
        "Stage-A miss": 15,
    }
    if counts != expected_counts:
        raise ValueError(f"unexpected EviGate-Bind end-to-end counts: {counts}")
    category_colors = {
        "Correct label": "#3A923A",
        "Wrong label": "#D55E00",
        "Unattributed after alert": "#9E9E9E",
        "Stage-A miss": "#D9D9D9",
    }
    y_pos = np.asarray([0])
    left = np.zeros(1)
    for category in category_colors:
        values = np.asarray([counts[category]])
        bars = ax2.barh(y_pos, values, left=left, height=0.58, color=category_colors[category], edgecolor="white", linewidth=0.45, label=category)
        for bar, value, start in zip(bars, values, left):
            if value >= 6:
                ax2.text(start + value / 2, bar.get_y() + bar.get_height() / 2, str(int(value)), ha="center", va="center", fontsize=5.8, color="white" if category != "Stage-A miss" else "#444444", fontweight="bold")
        left += values
    ax2.set_yticks(y_pos, ["EviGate-Bind"])
    ax2.set_ylim(-0.72, 0.72)
    ax2.set(xlim=(0, 51), xlabel="Non-pilot events in full pipeline (n = 51)")
    ax2.set_xticks([0, 10, 20, 30, 40, 51])
    ax2.grid(axis="x", color="#D9D9D9", linewidth=0.45, alpha=0.65, zorder=0)
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)
    cumulative = 0.0
    short_labels = {
        "Correct label": "Correct",
        "Wrong label": "Wrong",
        "Unattributed after alert": "Unattributed",
        "Stage-A miss": "Stage-A miss",
    }
    for category in category_colors:
        value = counts[category]
        ax2.text(
            cumulative + value / 2,
            0.48,
            short_labels[category],
            ha="center",
            va="center",
            fontsize=5.0,
            color=category_colors[category] if category != "Stage-A miss" else "#555555",
            fontweight="bold",
        )
        cumulative += value
    panel_label(ax2, "b", x=-0.16)
    save_figure(fig, output_dir / "figure2_selective_risk_end_to_end")

    write_csv(source_dir / "figure2a_risk_coverage.csv", risk_rows)
    evigate_accounting_rows = [
        {"method": "EviGate-Bind", **counts, "total_events": sum(counts.values())}
    ]
    write_csv(source_dir / "figure2b_evigate_end_to_end.csv", evigate_accounting_rows)

    # Preserve the original four-rule 53-event accounting artifact because it
    # remains part of the frozen conventional-selector audit, although panel b
    # now visualizes the final 51-event EviGate-Bind path.
    conventional_accounting_rows = []
    for rule in RULES:
        rule_counts = {
            "Correct label": sum(
                int(r[f"end_to_end_fixed_{rule}_correct_attribution"]) for r in event_rows
            ),
            "Wrong label": sum(
                int(r[f"end_to_end_fixed_{rule}_wrong_attribution"]) for r in event_rows
            ),
            "Unattributed after alert": sum(
                int(r[f"end_to_end_fixed_{rule}_unattributed_after_alert"]) for r in event_rows
            ),
            "Stage-A miss": sum(1 - int(r["stage_a_alerted"]) for r in event_rows),
        }
        conventional_accounting_rows.append(
            {"rule": rule, **rule_counts, "total_events": sum(rule_counts.values())}
        )
    write_csv(
        source_dir / "figure2b_end_to_end_accounting.csv",
        conventional_accounting_rows,
    )


def build_figure5(root: Path, output_dir: Path, source_dir: Path) -> None:
    """Summarize CICAPT robustness and the X-IIoTID transfer boundary."""

    bind_summary_path = (
        root
        / "data/derived/evigate_llm/v7_bindgate/evaluation_temporal/evigate_bindgate.summary.json"
    )
    xiiotid_summary_path = (
        root
        / "data/derived/xiiotid_binding_diagnostics_v2/xiiotid_binding_diagnostics.summary.json"
    )
    bind_summary = json.loads(bind_summary_path.read_text(encoding="utf-8"))
    xiiotid_summary = json.loads(xiiotid_summary_path.read_text(encoding="utf-8"))

    aggregate = bind_summary["aggregate"]
    cicapt_categories = ["Clean risk", "Five-family\nwrong-label", "Context\nwrong-label"]
    cicapt_baseline = np.asarray(
        [
            aggregate["matched_margin"]["clean"]["selective_risk"],
            aggregate["matched_margin"]["corruption_macro_wrong_label_rate"],
            aggregate["matched_margin"]["context_replacement"]["wrong_label_rate"],
        ]
    )
    cicapt_bind = np.asarray(
        [
            aggregate["cascade"]["clean"]["selective_risk"],
            aggregate["cascade"]["corruption_macro_wrong_label_rate"],
            aggregate["cascade"]["context_replacement"]["wrong_label_rate"],
        ]
    )

    families = xiiotid_summary["family_results"]
    xiiotid_categories = ["True-pair\nacceptance", "Hard mismatch\nalarm", "Random mismatch\nalarm"]
    xiiotid_values = {
        "BindGate": np.asarray(
            [
                families["true_pair"]["bind_accept_rate"],
                families["different_stage_hard"]["bind_alarm_rate"],
                families["different_stage_random"]["bind_alarm_rate"],
            ]
        ),
        "Affinity": np.asarray(
            [
                families["true_pair"]["affinity_accept_rate"],
                families["different_stage_hard"]["affinity_alarm_rate"],
                families["different_stage_random"]["affinity_alarm_rate"],
            ]
        ),
        "Posterior LR": np.asarray(
            [
                families["true_pair"]["concat_accept_rate"],
                families["different_stage_hard"]["concat_alarm_rate"],
                families["different_stage_random"]["concat_alarm_rate"],
            ]
        ),
    }

    fig = plt.figure(figsize=(7.2, 3.15))
    gs = fig.add_gridspec(
        1,
        2,
        width_ratios=(1.0, 1.15),
        wspace=0.30,
        left=0.075,
        right=0.99,
        bottom=0.22,
        top=0.87,
    )
    ax1 = fig.add_subplot(gs[0, 0])
    ax2 = fig.add_subplot(gs[0, 1])

    x1 = np.arange(len(cicapt_categories))
    width1 = 0.34
    bars1 = ax1.bar(
        x1 - width1 / 2,
        cicapt_baseline,
        width1,
        label="Matched margin + rules",
        color="#9AA7B8",
        edgecolor="#333333",
        linewidth=0.55,
        hatch="//",
    )
    bars2 = ax1.bar(
        x1 + width1 / 2,
        cicapt_bind,
        width1,
        label="EviGate-Bind",
        color="#0072B2",
        edgecolor="#333333",
        linewidth=0.55,
    )
    for bars in (bars1, bars2):
        for bar in bars:
            value = bar.get_height()
            ax1.text(
                bar.get_x() + bar.get_width() / 2,
                value + 0.025,
                f"{value:.3f}",
                ha="center",
                va="bottom",
                fontsize=5.6,
            )
    ax1.set_xticks(x1, cicapt_categories)
    ax1.set_ylim(0, 1.02)
    ax1.set_ylabel("Rate (lower is better)")
    ax1.set_title("CICAPT-IIoT robustness", fontweight="bold", pad=5)
    ax1.legend(loc="upper left", frameon=False, fontsize=5.8, handlelength=1.4)
    ax1.grid(axis="y", color="#D9D9D9", linewidth=0.45, alpha=0.65, zorder=0)
    clean_axes(ax1)
    panel_label(ax1, "a", x=-0.16)

    x2 = np.arange(len(xiiotid_categories))
    width2 = 0.24
    colors = {"BindGate": "#0072B2", "Affinity": "#E69F00", "Posterior LR": "#9AA7B8"}
    hatches = {"BindGate": "", "Affinity": "..", "Posterior LR": "//"}
    offsets = (-width2, 0.0, width2)
    for offset, (label, values) in zip(offsets, xiiotid_values.items()):
        bars = ax2.bar(
            x2 + offset,
            values,
            width2,
            label=label,
            color=colors[label],
            edgecolor="#333333",
            linewidth=0.55,
            hatch=hatches[label],
        )
        for bar in bars:
            value = bar.get_height()
            ax2.text(
                bar.get_x() + bar.get_width() / 2,
                value + 0.025,
                f"{value:.3f}",
                ha="center",
                va="bottom",
                fontsize=5.2,
                rotation=90 if value < 0.12 else 0,
            )
    ax2.set_xticks(x2, xiiotid_categories)
    ax2.set_ylim(0, 1.02)
    ax2.set_ylabel("Rate (higher is better)")
    ax2.set_title("X-IIoTID compatibility boundary", fontweight="bold", pad=5)
    ax2.legend(loc="upper center", bbox_to_anchor=(0.5, 1.0), ncol=3, frameon=False, fontsize=5.6, handlelength=1.2, columnspacing=0.8)
    ax2.grid(axis="y", color="#D9D9D9", linewidth=0.45, alpha=0.65, zorder=0)
    clean_axes(ax2)
    panel_label(ax2, "b", x=-0.14)

    save_figure(fig, output_dir / "figure5_robustness_transfer")
    source_rows: list[dict[str, Any]] = []
    for category, baseline, cascade in zip(cicapt_categories, cicapt_baseline, cicapt_bind):
        source_rows.extend(
            [
                {"panel": "a", "dataset": "CICAPT-IIoT", "metric": category.replace("\n", " "), "method": "Matched margin + structural rules", "rate": float(baseline), "n": 51},
                {"panel": "a", "dataset": "CICAPT-IIoT", "metric": category.replace("\n", " "), "method": "EviGate-Bind", "rate": float(cascade), "n": 51},
            ]
        )
    for category_index, category in enumerate(xiiotid_categories):
        for method, values in xiiotid_values.items():
            source_rows.append(
                {"panel": "b", "dataset": "X-IIoTID", "metric": category.replace("\n", " "), "method": method, "rate": float(values[category_index]), "n": 4400}
            )
    write_csv(source_dir / "figure5_robustness_transfer.csv", source_rows)


def build_figure3(root: Path, output_dir: Path, source_dir: Path) -> None:
    rows = read_csv(root / "data/derived/stage4_revision/diagnostics/stage4_corruption_comparison.csv")
    families = ["context_replacement", "process_deletion", "random_entity_deletion", "socket_type_deletion", "time_shift"]
    family_labels = ["Context replacement", "All-process deletion", "Hash-parity half-process deletion", "Socket-type deletion", "+600-s time shift"]
    wrong = np.asarray([[float(next(r["wrong_attribution_rate"] for r in rows if r["corruption_family"] == family and r["rule"] == rule)) for rule in RULES] for family in families])
    reject = np.asarray([[float(next(r["rejection_rate"] for r in rows if r["corruption_family"] == family and r["rule"] == rule)) for rule in RULES] for family in families])

    fig, axes = plt.subplots(1, 2, figsize=(7.2, 4.2), gridspec_kw={"wspace": 0.46, "left": 0.18, "right": 0.96, "bottom": 0.15, "top": 0.92})
    for ax, matrix, cmap, title, label in (
        (axes[0], wrong, "Reds", "Wrong-label rate", "a"),
        (axes[1], reject, "Blues", "Rejection rate", "b"),
    ):
        image = ax.imshow(matrix, vmin=0, vmax=1, cmap=cmap, aspect="auto", interpolation="nearest")
        ax.set_xticks(np.arange(4), [RULE_LABELS[r] for r in RULES], rotation=32, ha="right")
        ax.set_yticks(np.arange(5), family_labels)
        ax.set_title(title, pad=6, fontweight="bold")
        ax.tick_params(length=0)
        for i in range(matrix.shape[0]):
            for j in range(matrix.shape[1]):
                value = matrix[i, j]
                ax.text(j, i, f"{value:.2f}", ha="center", va="center", fontsize=6.1, color="white" if value >= 0.58 else "#222222", fontweight="bold" if value >= 0.75 else "normal")
        cbar = fig.colorbar(image, ax=ax, fraction=0.046, pad=0.035)
        cbar.set_ticks([0, 0.5, 1.0])
        cbar.ax.tick_params(labelsize=5.8, length=2)
        panel_label(ax, label, x=-0.22)
    axes[1].tick_params(labelleft=False)
    fig.text(0.57, 0.035, "Each cell: n = 53 transformed events; leave-one-corruption-family-out evaluation", ha="center", va="bottom", fontsize=5.7, color="#555555")
    save_figure(fig, output_dir / "figure3_corruption_response")
    write_csv(source_dir / "figure3_corruption_response.csv", rows)


def case_rankings(root: Path) -> dict[str, Any]:
    inputs_path = root / "data/derived/evigate_phase2_evidence/cases.inputs.jsonl"
    truth_path = root / "data/derived/evigate_phase2_evidence/cases.truth.jsonl"
    inputs = {item["case_id"]: item for item in load_jsonl(inputs_path)}
    truths = {item["case_id"]: item for item in load_jsonl(truth_path)}
    extracted = {case_id: extract_case(case) for case_id, case in inputs.items()}
    fold = int(next(item["fold"] for item in truths[CASE_ID]["split_membership"] if item["partition"] == "test"))
    train_ids = [case_id for case_id in sorted(inputs) if membership(truths[case_id], fold)["partition"] == "train"]
    x_train, y_train, weights, training_audit = training_data_for_ids(train_ids, inputs, truths, extracted)
    names = feature_names()
    configs = shortcut_configurations()
    entity_ids, matrix = extracted[CASE_ID]
    entity_map = {entity["entity_id"]: entity for entity in inputs[CASE_ID]["provenance_candidate_graph"]["entities"]}
    truth_ids = set(truths[CASE_ID]["provenance_ground_truth"]["malicious_candidate_process_ids"])
    rankings: dict[str, list[dict[str, Any]]] = {}
    for config_name in ("full", "without_all_process_semantics"):
        indices = [index for index, name in enumerate(names) if name in configs[config_name]]
        model = fit_logistic(x_train[:, indices], y_train, weights)
        scores = model.predict_proba(matrix[:, indices])[:, 1]
        ranked = sorted(zip(entity_ids, map(float, scores)), key=lambda item: (-item[1], item[0]))
        rankings[config_name] = []
        for rank, (entity_id, score) in enumerate(ranked, start=1):
            entity = entity_map[entity_id]
            attributes = entity.get("attributes", {})
            rankings[config_name].append(
                {
                    "configuration": config_name,
                    "rank": rank,
                    "entity_id": entity_id,
                    "pid": attributes.get("pid", ""),
                    "process_name": attributes.get("name", ""),
                    "executable": attributes.get("exe", ""),
                    "score": score,
                    "evaluation_truth": int(entity_id in truth_ids),
                }
            )

    stage_c = next(r for r in read_csv(root / "data/derived/stage_c/final_run/stage_c_test_predictions.csv") if r["case_id"] == CASE_ID)
    decomposed = next(r for r in read_csv(root / "data/derived/stage4_revision/stage_c_gate_decomposition/stage_c_gate_decomposition.test_predictions.csv") if r["case_id"] == CASE_ID)
    graph = inputs[CASE_ID]["provenance_candidate_graph"]
    alert = inputs[CASE_ID]["network_alert"]
    truth = truths[CASE_ID]
    return {
        "case_id": CASE_ID,
        "selection_note": "Representative test case fixed before plotting: candidate truth present, correct Stage-C label, nondegenerate gate outputs.",
        "test_fold": fold,
        "network_alert": alert,
        "graph_summary": {
            "entities": len(graph["entities"]),
            "process_candidates": sum(entity["entity_kind"] == "process" for entity in graph["entities"]),
            "relations": len(graph["relations"]),
        },
        "training_audit": training_audit,
        "rankings": rankings,
        "stage_c": stage_c,
        "gate_decomposition": decomposed,
        "evaluation_truth": {
            "tactic": truth["event"]["tactic"],
            "source_cluster_id": truth["source_cluster_id"],
            "malicious_candidate_process_ids": sorted(truth_ids),
            "malicious_candidate_pids": truth["provenance_ground_truth"]["malicious_candidate_pids"],
        },
    }


def process_label(row: dict[str, Any]) -> str:
    name = row["process_name"] or Path(row["executable"]).name or "process"
    return f"{name} (pid {row['pid']})"


def build_figure4(root: Path, output_dir: Path, source_dir: Path) -> None:
    case = case_rankings(root)
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "figure4_worked_case.json").write_text(json.dumps(case, indent=2) + "\n", encoding="utf-8")
    ranking_rows = case["rankings"]["full"] + case["rankings"]["without_all_process_semantics"]
    write_csv(source_dir / "figure4_rankings.csv", ranking_rows)

    fig, ax = plt.subplots(figsize=(7.2, 4.8))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.text(0.015, 0.97, "Representative test event", ha="left", va="top", fontsize=7.5, fontweight="bold")
    ax.text(0.985, 0.97, CASE_ID, ha="right", va="top", fontsize=5.7, color="#555555")

    alert = case["network_alert"]
    protocols = alert["protocol_counts"]
    rounded_box(
        ax,
        (0.02, 0.61),
        0.17,
        0.25,
        "Observed trigger",
        f"60-s window\n{alert['row_count']:,} rows; {int(alert['total_bytes']):,} B\nTCP {protocols.get('TCP', 0):,}\nUDP {protocols.get('UDP', 0):,}; ARP {protocols.get('ARP', 0):,}",
        facecolor="#EAF3F8",
        body_size=5.7,
    )
    graph = case["graph_summary"]
    rounded_box(
        ax,
        (0.225, 0.61),
        0.17,
        0.25,
        "Candidate context",
        f"±5-min candidate graph\n{graph['entities']} entities\n{graph['process_candidates']} process candidates\n{graph['relations']} relations",
        facecolor="#F0F7EE",
        title_size=5.8,
        body_size=5.7,
    )
    arrow(ax, (0.19, 0.735), (0.225, 0.735))

    rounded_box(
        ax,
        (0.43, 0.52),
        0.285,
        0.37,
        "Stage B: candidate ranking",
        "",
        facecolor="#F7FAF5",
    )
    full = case["rankings"]["full"][:3]
    masked = case["rankings"]["without_all_process_semantics"][:3]
    ax.text(0.445, 0.825, "Full features", transform=ax.transAxes, ha="left", va="top", fontsize=5.8, fontweight="bold", color="#17365D")
    ax.text(0.585, 0.825, "Process semantics\nmasked", transform=ax.transAxes, ha="left", va="top", fontsize=5.8, fontweight="bold", color="#17365D", linespacing=1.0)
    for idx, row in enumerate(full):
        ax.text(0.445, 0.785 - idx * 0.075, f"{idx+1}. {process_label(row)}\n   score {row['score']:.3f}", transform=ax.transAxes, ha="left", va="top", fontsize=5.2, linespacing=1.1)
    for idx, row in enumerate(masked):
        ax.text(0.585, 0.765 - idx * 0.075, f"{idx+1}. {process_label(row)}\n   score {row['score']:.3f}", transform=ax.transAxes, ha="left", va="top", fontsize=5.0, linespacing=1.1)
    ax.text(0.445, 0.545, "Scores are ranker-specific.", transform=ax.transAxes, ha="left", va="bottom", fontsize=5.0, color="#555555")
    arrow(ax, (0.395, 0.735), (0.43, 0.735))

    rounded_box(
        ax,
        (0.75, 0.52),
        0.225,
        0.37,
        "Stage C: tactic posterior",
        "",
        facecolor="#F8F0F6",
    )
    inset = ax.inset_axes([0.815, 0.585, 0.135, 0.23])
    tactic_keys = ["collection", "command_and_control", "credential_access", "discovery", "exfiltration"]
    tactic_labels = ["Collection", "C2", "Credential", "Discovery", "Exfiltration"]
    probabilities = [float(case["stage_c"][f"probability_{key}"]) for key in tactic_keys]
    order = np.arange(len(tactic_keys))[::-1]
    bar_colors = ["#8D6CAB" if key == "collection" else "#C8B8D8" for key in tactic_keys]
    inset.barh(order, probabilities, color=bar_colors, height=0.62)
    inset.set_yticks(order, tactic_labels)
    inset.set_xlim(0, 0.40)
    inset.set_xticks([0, 0.2, 0.4])
    inset.tick_params(labelsize=5.0, length=2)
    inset.spines["top"].set_visible(False)
    inset.spines["right"].set_visible(False)
    inset.set_xlabel("Posterior", fontsize=5.0, labelpad=1)
    arrow(ax, (0.715, 0.735), (0.75, 0.735))

    gate = case["gate_decomposition"]
    if not all(int(gate[f"fixed_coverage_{rule}_accept"]) for rule in RULES):
        raise AssertionError("worked-case frozen-rule status changed")
    calibrated_issued = [RULE_LABELS[rule] for rule in RULES if int(gate[f"calibrated_{rule}_accept"])]
    calibrated_withheld = [RULE_LABELS[rule] for rule in RULES if not int(gate[f"calibrated_{rule}_accept"])]
    rounded_box(
        ax,
        (0.43, 0.09),
        0.545,
        0.28,
        "Selection outcome",
        f"Predicted tactic: {case['stage_c']['prediction'].replace('_', ' ')}\nFrozen 42/53 rule: all four selectors issue\nCalibration transfer: {' / '.join(calibrated_issued)} issue\n{' / '.join(calibrated_withheld)} withholds (insufficient evidence)",
        facecolor="#F7F2FA",
        body_size=5.5,
    )
    arrow(ax, (0.86, 0.52), (0.86, 0.37))

    rounded_box(
        ax,
        (0.02, 0.09),
        0.375,
        0.28,
        "Evaluation-only truth (not an input)",
        "Derived tactic: Collection\nMalicious PID: 37937\nFull ranker: truth at rank 1\nMasked ranker: truth midrank 1.5\nStage-C tactic label: correct",
        facecolor="#FAFAFA",
        edgecolor="#888888",
        linestyle="--",
        title_color="#555555",
        body_size=5.7,
    )
    ax.text(0.02, 0.02, "This event illustrates the interface; aggregate performance and failure rates are reported in the main results.", transform=ax.transAxes, ha="left", va="bottom", fontsize=5.5, color="#555555")
    save_figure(fig, output_dir / "figure4_worked_event")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=ROOT / "paper/figures")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_style()
    source_dir = args.output_dir / "source_data"
    build_figure1(args.output_dir, source_dir)
    build_figure2(ROOT, args.output_dir, source_dir)
    build_figure3(ROOT, args.output_dir, source_dir)
    build_figure4(ROOT, args.output_dir, source_dir)
    build_figure5(ROOT, args.output_dir, source_dir)
    print(json.dumps({"status": "ok", "figures": 5, "output_dir": str(args.output_dir)}, indent=2))


if __name__ == "__main__":
    main()
