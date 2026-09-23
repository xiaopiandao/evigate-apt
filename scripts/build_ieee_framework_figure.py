#!/usr/bin/env python3
"""Build the redesigned IEEE framework diagram for EviGate-APT."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil

import matplotlib as mpl

mpl.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Circle, FancyArrowPatch, FancyBboxPatch


ROOT = Path(__file__).resolve().parents[1]
NAVY = "#17365D"
INK = "#27323C"
LINE = "#596675"
MUTED = "#68727D"
BLUE = "#2F78A8"
GREEN = "#5B8A5A"
PURPLE = "#8064A2"
AMBER = "#B36B00"
STAGE_COLORS = (BLUE, GREEN, PURPLE, AMBER)
STAGE_FILLS = ("#EEF6FB", "#F1F7EE", "#F7F1F8", "#FFF6E7")


def configure_style() -> None:
    mpl.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
            "font.size": 8,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "svg.fonttype": "none",
            "axes.unicode_minus": False,
            "figure.facecolor": "white",
            "savefig.facecolor": "white",
        }
    )


def rounded(
    ax: plt.Axes,
    x: float,
    y: float,
    w: float,
    h: float,
    *,
    face: str = "white",
    edge: str = LINE,
    lw: float = 0.9,
    linestyle: str = "-",
    radius: float = 0.014,
    zorder: int = 1,
) -> FancyBboxPatch:
    patch = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle=f"round,pad=0.006,rounding_size={radius}",
        linewidth=lw,
        edgecolor=edge,
        facecolor=face,
        linestyle=linestyle,
        transform=ax.transAxes,
        zorder=zorder,
    )
    ax.add_patch(patch)
    return patch


def arrow(
    ax: plt.Axes,
    start: tuple[float, float],
    end: tuple[float, float],
    *,
    color: str = LINE,
    lw: float = 1.0,
    linestyle: str = "-",
    connectionstyle: str = "arc3",
    zorder: int = 4,
) -> None:
    ax.add_patch(
        FancyArrowPatch(
            start,
            end,
            arrowstyle="-|>",
            mutation_scale=8.5,
            linewidth=lw,
            color=color,
            linestyle=linestyle,
            connectionstyle=connectionstyle,
            transform=ax.transAxes,
            clip_on=False,
            zorder=zorder,
        )
    )


def stage_panel(
    ax: plt.Axes,
    *,
    x: float,
    y: float,
    w: float,
    h: float,
    number: int,
    title: str,
    color: str,
    fill: str,
) -> None:
    rounded(ax, x, y, w, h, face="white", edge=color, lw=1.1, radius=0.016)
    header_h = 0.105
    header = FancyBboxPatch(
        (x, y + h - header_h),
        w,
        header_h,
        boxstyle="round,pad=0.006,rounding_size=0.016",
        linewidth=0,
        facecolor=fill,
        transform=ax.transAxes,
        zorder=2,
    )
    ax.add_patch(header)
    # Cover the lower header corner rounding for a clean horizontal division.
    ax.add_patch(
        plt.Rectangle(
            (x, y + h - header_h),
            w,
            header_h * 0.48,
            transform=ax.transAxes,
            facecolor=fill,
            edgecolor="none",
            zorder=2,
        )
    )
    circle = Circle(
        (x + 0.028, y + h - header_h / 2),
        0.0175,
        transform=ax.transAxes,
        facecolor=color,
        edgecolor="none",
        zorder=3,
    )
    ax.add_patch(circle)
    ax.text(
        x + 0.028,
        y + h - header_h / 2,
        str(number),
        transform=ax.transAxes,
        ha="center",
        va="center",
        fontsize=7,
        fontweight="bold",
        color="white",
        zorder=4,
    )
    ax.text(
        x + 0.053,
        y + h - header_h / 2,
        title,
        transform=ax.transAxes,
        ha="left",
        va="center",
        fontsize=9,
        fontweight="bold",
        color=NAVY,
        zorder=4,
    )
    ax.plot(
        [x, x + w],
        [y + h - header_h, y + h - header_h],
        transform=ax.transAxes,
        color=color,
        linewidth=0.65,
        zorder=3,
    )


def label(ax: plt.Axes, x: float, y: float, text: str, color: str) -> None:
    ax.text(
        x,
        y,
        text.upper(),
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=6.3,
        fontweight="bold",
        color=color,
    )


def content(ax: plt.Axes, x: float, y: float, text: str, *, size: float = 7.35) -> None:
    ax.text(
        x,
        y,
        text,
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=size,
        color=INK,
        linespacing=1.16,
    )


def pill(
    ax: plt.Axes,
    x: float,
    y: float,
    w: float,
    h: float,
    text: str,
    *,
    face: str,
    edge: str,
    color: str = INK,
    linestyle: str = "-",
    fontsize: float = 6.9,
) -> None:
    rounded(
        ax,
        x,
        y,
        w,
        h,
        face=face,
        edge=edge,
        lw=0.75,
        linestyle=linestyle,
        radius=0.010,
        zorder=3,
    )
    ax.text(
        x + w / 2,
        y + h / 2,
        text,
        transform=ax.transAxes,
        ha="center",
        va="center",
        fontsize=fontsize,
        color=color,
        zorder=4,
    )


def build_framework() -> tuple[plt.Figure, dict]:
    fig, ax = plt.subplots(figsize=(7.16, 3.18))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(
        0.025,
        0.955,
        "ONLINE INFERENCE",
        transform=ax.transAxes,
        ha="left",
        va="center",
        fontsize=7.2,
        fontweight="bold",
        color=NAVY,
    )
    ax.plot([0.14, 0.975], [0.936, 0.936], transform=ax.transAxes, color="#B7C0C9", linewidth=0.65)
    ax.text(
        0.975,
        0.955,
        "solid: deployed path   dashed orange: post-freeze extension",
        transform=ax.transAxes,
        ha="right",
        va="center",
        fontsize=6.4,
        color=MUTED,
    )

    xs = [0.025, 0.267, 0.509, 0.751]
    y, w, h = 0.385, 0.214, 0.505
    titles = ["Trigger", "Retrieve", "Certify", "Gate"]
    for idx, (x, title, color, fill) in enumerate(
        zip(xs, titles, STAGE_COLORS, STAGE_FILLS), start=1
    ):
        stage_panel(
            ax,
            x=x,
            y=y,
            w=w,
            h=h,
            number=idx,
            title=title,
            color=color,
            fill=fill,
        )

    # Stage 1: independent network trigger.
    label(ax, xs[0] + 0.017, 0.747, "network view", BLUE)
    content(ax, xs[0] + 0.017, 0.708, "60-s PCAP/flow window\nNo host-log input")
    pill(
        ax,
        xs[0] + 0.017,
        0.535,
        w - 0.034,
        0.075,
        "Stage A alert model",
        face="#E4F1F8",
        edge=BLUE,
        color=NAVY,
        fontsize=7.2,
    )
    label(ax, xs[0] + 0.017, 0.495, "emits", BLUE)
    content(ax, xs[0] + 0.017, 0.458, "alert  |  no_alert", size=7.2)

    # Stage 2: alert-opened provenance retrieval.
    label(ax, xs[1] + 0.017, 0.747, "host evidence", GREEN)
    content(ax, xs[1] + 0.017, 0.708, "±5-min alert-opened\nprovenance graph")
    pill(
        ax,
        xs[1] + 0.017,
        0.535,
        w - 0.034,
        0.075,
        "Typed Stage B ranker",
        face="#EAF4E7",
        edge=GREEN,
        color=NAVY,
        fontsize=7.2,
    )
    label(ax, xs[1] + 0.017, 0.495, "emits", GREEN)
    content(ax, xs[1] + 0.017, 0.458, "ranked processes", size=7.2)

    # Stage 3: proposal locking and machine-verifiable certificate checks.
    label(ax, xs[2] + 0.017, 0.747, "proposal", PURPLE)
    content(ax, xs[2] + 0.017, 0.708, "Stage C posterior + tactic")
    content(ax, xs[2] + 0.017, 0.662, "Proposal-locked package", size=6.8)
    pill(
        ax,
        xs[2] + 0.017,
        0.535,
        0.084,
        0.064,
        "Optional LLM",
        face="#F6EEF7",
        edge=PURPLE,
        color=NAVY,
        linestyle="--",
        fontsize=5.8,
    )
    arrow(
        ax,
        (xs[2] + 0.104, 0.567),
        (xs[2] + 0.126, 0.567),
        color=PURPLE,
        lw=0.75,
    )
    pill(
        ax,
        xs[2] + 0.127,
        0.535,
        0.070,
        0.064,
        "Verifier",
        face="#F6EEF7",
        edge=PURPLE,
        color=NAVY,
        fontsize=6.7,
    )
    label(ax, xs[2] + 0.017, 0.500, "checks", PURPLE)
    content(
        ax,
        xs[2] + 0.017,
        0.455,
        "schema / ownership / nullable fields\nCPU path bypasses LLM",
        size=5.0,
    )

    # Stage 4: separate comparator and post-freeze deployable path.
    label(ax, xs[3] + 0.017, 0.747, "compare", AMBER)
    pill(
        ax,
        xs[3] + 0.017,
        0.625,
        w - 0.034,
        0.074,
        "confidence • margin\nintegrity • dual",
        face="#F3F4F5",
        edge="#8A929A",
        color=INK,
        fontsize=6.35,
    )
    label(ax, xs[3] + 0.017, 0.605, "deploy", AMBER)
    pill(
        ax,
        xs[3] + 0.017,
        0.485,
        w - 0.034,
        0.074,
        "BindGate + margin\n+ temporal admissibility",
        face="#FFF1D7",
        edge=AMBER,
        color=NAVY,
        linestyle="--",
        fontsize=6.45,
    )
    label(ax, xs[3] + 0.017, 0.450, "decision", AMBER)
    content(ax, xs[3] + 0.017, 0.415, "issue label  |  withhold", size=6.85)

    # Main left-to-right inference path.
    for idx in range(3):
        arrow(
            ax,
            (xs[idx] + w + 0.003, 0.637),
            (xs[idx + 1] - 0.006, 0.637),
            color=STAGE_COLORS[idx + 1],
            lw=1.05,
        )

    # Evaluation sidecar and final three-state record.
    rounded(
        ax,
        0.025,
        0.115,
        0.255,
        0.175,
        face="#FAFAFA",
        edge="#8A8A8A",
        lw=0.9,
        linestyle="--",
        radius=0.014,
    )
    ax.text(
        0.042,
        0.260,
        "EVALUATION SIDECAR",
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=7.1,
        fontweight="bold",
        color="#555555",
    )
    ax.text(
        0.042,
        0.211,
        "group splits • truth IDs\nderived labels • metrics\nnever enters inference",
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=6.05,
        color=INK,
        linespacing=1.08,
    )

    rounded(
        ax,
        0.305,
        0.115,
        0.660,
        0.175,
        face="#F4F7FA",
        edge=NAVY,
        lw=1.0,
        radius=0.014,
    )
    ax.text(
        0.325,
        0.267,
        "THREE-STATE ANALYST RECORD",
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=7.2,
        fontweight="bold",
        color=NAVY,
    )
    outcome_y = 0.176
    outcome_specs = [
        (0.325, 0.125, "no_alert", "#ECEEEF", "#7B838B"),
        (0.461, 0.190, "alert_unattributed", "#FFF1D7", AMBER),
        (0.662, 0.160, "alert_attributed", "#E8F2E5", GREEN),
    ]
    for ox, ow, text, face, edge in outcome_specs:
        pill(
            ax,
            ox,
            outcome_y,
            ow,
            0.047,
            text,
            face=face,
            edge=edge,
            color=INK,
            fontsize=6.6,
        )
    pill(
        ax,
        0.833,
        outcome_y,
        0.112,
        0.047,
        "certificate / refusal\n+ integrity alarm",
        face="#EEF3F8",
        edge=NAVY,
        color=INK,
        fontsize=5.45,
    )

    # Explicit termination and reporting routes.
    arrow(
        ax,
        (xs[3] + w / 2, y),
        (xs[3] + w / 2, 0.292),
        color=AMBER,
        lw=1.05,
        linestyle="--",
    )
    ax.plot(
        [xs[0] + 0.055, xs[0] + 0.055, 0.315],
        [y, 0.318, 0.318],
        transform=ax.transAxes,
        color="#7D858D",
        linewidth=0.85,
        linestyle=(0, (3, 2)),
        zorder=2,
    )
    arrow(
        ax,
        (0.315, 0.318),
        (0.315, 0.292),
        color="#7D858D",
        lw=0.85,
        linestyle="--",
    )
    ax.text(
        0.094,
        0.322,
        "no_alert terminates here",
        transform=ax.transAxes,
        ha="left",
        va="bottom",
        fontsize=6.3,
        color=MUTED,
    )

    ax.text(
        0.025,
        0.050,
        "Boundary:",
        transform=ax.transAxes,
        ha="left",
        va="center",
        fontsize=6.8,
        fontweight="bold",
        color=NAVY,
    )
    ax.text(
        0.108,
        0.050,
        "the alert opens a temporally associated host graph; the framework does not assert a packet-to-process causal edge.",
        transform=ax.transAxes,
        ha="left",
        va="center",
        fontsize=6.8,
        color=MUTED,
    )

    source = {
        "figure": 1,
        "layout": "four-stage online inference with separate evaluation sidecar and three-state record",
        "stages": [
            {"number": 1, "name": "Trigger", "input": "60-s PCAP/flow window", "operation": "Stage A alert model", "output": ["alert", "no_alert"]},
            {"number": 2, "name": "Retrieve", "input": "alert-opened ±5-min provenance graph", "operation": "typed Stage B ranker", "output": "ranked processes"},
            {"number": 3, "name": "Certify", "input": "Stage C posterior and proposal-locked package", "operation": ["optional LLM auditor", "deterministic verifier"]},
            {"number": 4, "name": "Gate", "operation": ["conventional selector comparison", "post-freeze BindGate + margin + time"]},
        ],
        "inference_output": ["no_alert", "alert_unattributed", "alert_attributed"],
        "evaluation_only": ["group splits", "malicious-process IDs", "derived tactic labels", "metrics"],
        "non_claim": "The alert opens a temporally associated graph; no packet-to-process causal edge is asserted.",
    }
    return fig, source


def save(fig: plt.Figure, stem: Path) -> list[Path]:
    stem.parent.mkdir(parents=True, exist_ok=True)
    fixed_date = datetime(2026, 9, 17, tzinfo=timezone.utc)
    metadata = {
        "Creator": "EviGate-APT build_ieee_framework_figure.py",
        "Title": stem.name,
    }
    outputs: list[Path] = []
    svg = stem.with_suffix(".svg")
    fig.savefig(svg, bbox_inches="tight", pad_inches=0.035, metadata=metadata)
    outputs.append(svg)
    pdf = stem.with_suffix(".pdf")
    fig.savefig(
        pdf,
        bbox_inches="tight",
        pad_inches=0.035,
        metadata={**metadata, "CreationDate": fixed_date, "ModDate": fixed_date},
    )
    outputs.append(pdf)
    png = stem.with_suffix(".png")
    fig.savefig(png, dpi=600, bbox_inches="tight", pad_inches=0.035)
    outputs.append(png)
    tiff = stem.with_suffix(".tiff")
    fig.savefig(
        tiff,
        dpi=600,
        bbox_inches="tight",
        pad_inches=0.035,
        pil_kwargs={"compression": "tiff_lzw"},
    )
    outputs.append(tiff)
    return outputs


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "output" / "figures" / "ieee",
    )
    parser.add_argument(
        "--manuscript-figure-dir",
        type=Path,
        default=ROOT / "paper" / "figures",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_style()
    fig, source = build_framework()
    bundle_stem = args.output_dir / "figure1_framework_redesign"
    outputs = save(fig, bundle_stem)
    plt.close(fig)

    args.manuscript_figure_dir.mkdir(parents=True, exist_ok=True)
    for path in outputs:
        shutil.copy2(
            path,
            args.manuscript_figure_dir
            / f"figure1_pipeline_evidence_boundary{path.suffix}",
        )
    source_path = args.output_dir / "source_data" / "figure1_framework_source.json"
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text(json.dumps(source, indent=2) + "\n", encoding="utf-8")
    manuscript_source_path = (
        args.manuscript_figure_dir / "source_data" / "figure1_source.json"
    )
    manuscript_source_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, manuscript_source_path)
    print(json.dumps({"status": "ok", "outputs": [str(path) for path in outputs]}, indent=2))


if __name__ == "__main__":
    main()
