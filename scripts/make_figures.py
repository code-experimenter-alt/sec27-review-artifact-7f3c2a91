#!/usr/bin/env python3
"""Generate the editable-vector manuscript figures."""

from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch


OUT = Path(__file__).resolve().parents[1] / "figures"
OUT.mkdir(parents=True, exist_ok=True)

BLUE = "#0072B2"
TEAL = "#00897B"
VERMILION = "#D55E00"
GRAY = "#666666"
LIGHT_BLUE = "#E8F3F8"
LIGHT_TEAL = "#E5F3F1"
LIGHT_RED = "#FBEDE7"
LIGHT_GRAY = "#F3F4F5"
INK = "#1F2933"


mpl.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 9,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "svg.fonttype": "none",
        "axes.linewidth": 0.7,
    }
)


def _box(ax, x, y, w, h, title, body, edge, fill, title_size=7.8, body_size=7.0):
    patch = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0.32,rounding_size=0.8",
        linewidth=1.15,
        edgecolor=edge,
        facecolor=fill,
        zorder=2,
    )
    ax.add_patch(patch)
    ax.text(
        x + w / 2,
        y + h * 0.68,
        title,
        ha="center",
        va="center",
        fontsize=title_size,
        fontweight="bold",
        color=INK,
        zorder=3,
    )
    if body:
        ax.text(
            x + w / 2,
            y + h * 0.30,
            body,
            ha="center",
            va="center",
            fontsize=body_size,
            color=INK,
            linespacing=1.18,
            zorder=3,
        )
    return patch


def _arrow(ax, start, end, color=TEAL, style="-", width=1.25, mutation=10, z=1):
    arrow = FancyArrowPatch(
        start,
        end,
        arrowstyle="-|>",
        mutation_scale=mutation,
        linewidth=width,
        linestyle=style,
        color=color,
        shrinkA=0,
        shrinkB=0,
        zorder=z,
    )
    ax.add_patch(arrow)
    return arrow


def make_design_figure():
    fig, ax = plt.subplots(figsize=(7.0, 3.94))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 56.25)
    ax.axis("off")

    ax.add_patch(
        FancyBboxPatch(
            (0.8, 12.0),
            82.5,
            41.5,
            boxstyle="round,pad=0.25,rounding_size=1.2",
            facecolor="white",
            edgecolor=BLUE,
            linewidth=0.9,
            zorder=0,
        )
    )
    ax.add_patch(
        FancyBboxPatch(
            (84.2, 12.0),
            15.0,
            41.5,
            boxstyle="round,pad=0.25,rounding_size=1.2",
            facecolor="white",
            edgecolor=TEAL,
            linewidth=0.9,
            zorder=0,
        )
    )
    ax.text(42.0, 51.4, "TRAPS edge", ha="center", va="center", color=BLUE, fontsize=9.5, fontweight="bold")
    ax.text(91.7, 51.4, "Backend", ha="center", va="center", color=TEAL, fontsize=9.5, fontweight="bold")

    _box(ax, 2.0, 34.0, 10.0, 10.0, "Request", "account +\ncredential", GRAY, LIGHT_GRAY)
    _box(ax, 16.0, 34.0, 21.0, 10.0, "Exact active scope", "generation + version\ncertificate agrees", BLUE, LIGHT_BLUE)
    _box(ax, 42.0, 34.0, 16.0, 10.0, "One-sided screen", "MISS = nonmember\nHIT = continue", BLUE, LIGHT_BLUE)
    _box(ax, 63.0, 34.0, 18.0, 10.0, "Exact exception", "key + active version\nMISS = coalesce", VERMILION, LIGHT_RED)
    _box(ax, 87.0, 34.0, 10.5, 10.0, "Verifier", "authoritative", TEAL, LIGHT_TEAL, 7.5, 6.8)

    _arrow(ax, (12.0, 39.0), (16.0, 39.0), color=INK)
    _arrow(ax, (37.0, 39.0), (42.0, 39.0), color=BLUE)
    _arrow(ax, (58.0, 39.0), (63.0, 39.0), color=TEAL)
    ax.text(60.5, 40.0, "hit", ha="center", va="bottom", fontsize=7.2, color=TEAL)

    # Authorized local rejection paths.
    _box(ax, 41.0, 22.0, 18.0, 7.5, "LOCAL REJECT", "certified nonmember", VERMILION, LIGHT_RED, 8.0, 7.0)
    _box(ax, 62.0, 22.0, 20.0, 7.5, "LOCAL REJECT", "confirmed mismatch", VERMILION, LIGHT_RED, 8.0, 7.0)
    _arrow(ax, (50.0, 34.0), (50.0, 29.5), color=VERMILION)
    ax.text(50.9, 31.8, "miss", ha="left", va="center", fontsize=7.2, color=VERMILION)
    _arrow(ax, (72.0, 34.0), (72.0, 29.5), color=VERMILION)
    ax.text(72.9, 31.8, "hit", ha="left", va="center", fontsize=7.2, color=VERMILION)

    # Cache miss reaches a coalesced verifier call.
    _arrow(ax, (81.0, 39.0), (87.0, 39.0), color=TEAL)

    # Every ambiguous state joins one fail-open route.
    ax.plot([26.5, 92.0], [16.0, 16.0], color=GRAY, linewidth=1.1, linestyle=(0, (3, 2)), zorder=0)
    _arrow(ax, (26.5, 34.0), (26.5, 16.0), color=GRAY, style=(0, (3, 2)), width=1.0)
    _arrow(ax, (72.0, 34.0), (72.0, 16.0), color=GRAY, style=(0, (3, 2)), width=1.0)
    _arrow(ax, (92.0, 16.0), (92.0, 34.0), color=GRAY, style=(0, (3, 2)), width=1.0)
    ax.text(43.5, 14.5, "missing, stale, or ambiguous  ->  FORWARD (fail open)", ha="center", va="center", fontsize=7.5, color=GRAY)

    # Only one typed outcome may feed the cache; rotation invalidates its scope.
    ax.plot([92.0, 92.0, 79.0], [34.0, 8.5, 8.5], color=TEAL, linewidth=1.15, zorder=0)
    _arrow(ax, (79.0, 8.5), (79.0, 34.0), color=TEAL, width=1.15)
    ax.text(87.0, 9.6, "typed mismatch only", ha="center", va="bottom", fontsize=7.0, color=TEAL)
    _box(ax, 64.5, 3.6, 12.0, 7.0, "Version rotates", "old entry inactive", GRAY, LIGHT_GRAY, 7.2, 6.6)
    _arrow(ax, (70.5, 10.6), (70.5, 34.0), color=GRAY, style=(0, (3, 2)), width=1.0)

    ax.text(
        2.0,
        0.8,
        "A screen hit never authenticates; only the backend accepts credentials.",
        ha="left",
        va="bottom",
        fontsize=7.6,
        color=INK,
        fontweight="bold",
    )

    fig.savefig(OUT / "traps-design.pdf")
    fig.savefig(OUT / "traps-design.svg")
    fig.savefig(OUT / "traps-design-preview.png", dpi=220)
    plt.close(fig)


def _bound_panel(ax, means, bounds, threshold, title, subtitle, xlim, ticks, bound_kind):
    labels = ["PBKDF2-310k", "Argon2id-19 MiB"]
    colors = [BLUE, VERMILION]
    markers = ["o", "s"]
    y_positions = [1.0, 0.0]
    ax.axvline(threshold, color=INK, linewidth=1.0, linestyle=(0, (4, 3)), zorder=0)
    ax.text(threshold, 1.42, f"{threshold:g}x {subtitle}", ha="center", va="bottom", fontsize=8.0, color=INK)
    for label, color, marker, y, mean, bound in zip(labels, colors, markers, y_positions, means, bounds):
        lo, hi = (bound, mean) if bound_kind == "lower" else (mean, bound)
        ax.hlines(y, lo, hi, color=color, linewidth=2.0, zorder=2)
        ax.vlines(bound, y - 0.11, y + 0.11, color=color, linewidth=1.5, zorder=2)
        ax.scatter([mean], [y], s=55, marker=marker, facecolor=color, edgecolor="white", linewidth=0.6, zorder=3)
        ax.text(xlim[0] - (xlim[1] - xlim[0]) * 0.035, y, label, ha="right", va="center", fontsize=8.3, color=color, fontweight="bold")
        ax.text(mean, y + 0.20, f"{mean:.3f}", ha="center", va="bottom", fontsize=8.0, color=color)
        ax.text(bound, y - 0.20, f"{bound:.3f}", ha="center", va="top", fontsize=7.7, color=color)
    ax.set_title(title, fontsize=9.4, fontweight="bold", pad=16, color=INK)
    ax.set_xlim(*xlim)
    ax.set_ylim(-0.50, 1.55)
    ax.set_xticks(ticks)
    ax.set_yticks([])
    ax.grid(axis="x", color="#D7DCE0", linewidth=0.5, zorder=0)
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.tick_params(axis="x", labelsize=7.8, colors=INK)
    ax.set_xlabel("ratio (x)", fontsize=8.2, color=INK, labelpad=2)


def make_results_figure():
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 3.33), gridspec_kw={"wspace": 0.44})
    _bound_panel(
        axes[0],
        means=[5.578, 4.334],
        bounds=[5.145, 3.730],
        threshold=1.5,
        title="(a) Sustainable invalid-load ratio",
        subtitle="required",
        xlim=(1.0, 6.4),
        ticks=[1, 2, 3, 4, 5, 6],
        bound_kind="lower",
    )
    _bound_panel(
        axes[1],
        means=[0.373, 0.947],
        bounds=[0.526, 1.006],
        threshold=1.05,
        title="(b) Legitimate p99 latency ratio",
        subtitle="margin",
        xlim=(0.0, 1.20),
        ticks=[0.0, 0.3, 0.6, 0.9, 1.2],
        bound_kind="upper",
    )
    fig.text(
        0.5,
        0.015,
        "20 paired seeds per verifier; synthetic in-process service. Panel (b): 16 legitimate + 32 invalid req/s. No network/TLS claim.",
        ha="center",
        va="bottom",
        fontsize=7.7,
        color=INK,
    )
    fig.subplots_adjust(left=0.18, right=0.985, top=0.79, bottom=0.23)
    fig.savefig(OUT / "traps-service-results.pdf")
    fig.savefig(OUT / "traps-service-results.svg")
    fig.savefig(OUT / "traps-service-results-preview.png", dpi=220)
    plt.close(fig)


if __name__ == "__main__":
    make_design_figure()
    make_results_figure()
