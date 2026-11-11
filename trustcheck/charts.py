"""Charts for the "How good is it?" page (Altair, which ships with Streamlit).

Colors follow a validated colorblind-safe categorical palette, assigned to systems in a
FIXED order, so a system keeps its color on every chart. Single-measure charts use one hue.
"""
from __future__ import annotations

import altair as alt
import pandas as pd

INK, MUTED, GRID = "#1B2A4A", "#52607A", "#E3E8F0"
BODY = "Atkinson Hyperlegible, Helvetica, Arial, sans-serif"
HEAD = "Bricolage Grotesque, Helvetica, Arial, sans-serif"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]

# fixed slot per system family, so colors never shuffle when a run adds/removes systems
ORDER_HINTS = ["classic", "rules [no defense]", "rules", "llm_only", "agent"]


def system_order(names) -> list[str]:
    def key(n):
        for i, h in enumerate(ORDER_HINTS):
            if n.startswith(h):
                return (i, n)
        return (len(ORDER_HINTS), n)
    return sorted(dict.fromkeys(names), key=key)


def friendly(name: str) -> str:
    n = name.replace("classic_tfidf_lr", "Classic ML (TF-IDF)")
    n = n.replace("rules_only", "Rules only").replace("rules [no defense]", "Rules, no defense")
    n = n.replace("rules [defense]", "Rules + defense")
    n = n.replace("llm_only[", "LLM only (").replace("agent[", "TrustCheck agent (").replace("]", ")")
    return n


def _base(chart):
    return chart.configure_view(stroke=None).configure_axis(
        labelColor=MUTED, titleColor=MUTED, gridColor=GRID, domainColor=GRID, tickColor=GRID,
        labelFont=BODY, titleFont=BODY, labelFontSize=12,
    ).configure_legend(labelFont=BODY, labelColor=INK, labelFontSize=12
    ).configure_title(font=HEAD, color=INK, fontSize=16, anchor="start", offset=12)


def bar_by_system(df: pd.DataFrame, value: str, title: str, fmt: str = ".0%", color: str = SERIES[0],
                  lower_is_better: bool = True) -> alt.Chart:
    d = df[["system", value]].copy()
    d["System"] = d["system"].map(friendly)
    d = d.sort_values(value, ascending=lower_is_better)
    order = list(d["System"])
    enc_x = alt.X(f"{value}:Q", title=None, axis=alt.Axis(format=fmt, tickCount=4, grid=True),
                  scale=alt.Scale(domain=[0, max(1.0, float(d[value].max()))] if fmt.endswith("%") else alt.Undefined))
    bars = alt.Chart(d).mark_bar(color=color, cornerRadiusEnd=4, height=18).encode(
        y=alt.Y("System:N", sort=order, title=None, axis=alt.Axis(labelLimit=260, ticks=False, domain=False)),
        x=enc_x,
        tooltip=[alt.Tooltip("System:N"), alt.Tooltip(f"{value}:Q", format=fmt, title=title)],
    )
    labels = bars.mark_text(align="left", dx=6, color=INK, fontSize=12, font=BODY).encode(
        text=alt.Text(f"{value}:Q", format=fmt))
    return _base((bars + labels).properties(title=title, height=max(90, 34 * len(d)), width="container"))


def redteam_chart(rt: pd.DataFrame) -> alt.Chart:
    d = rt.copy()
    systems = system_order(d["system"])
    d["System"] = d["system"].map(friendly)
    names = [friendly(s) for s in systems]
    attacks = list(dict.fromkeys(d["attack"]))
    base = alt.Chart().encode(
        y=alt.Y("System:N", sort=names, title=None, axis=None),
        x=alt.X("attack_success_rate:Q", title="Share of scams the disguise sneaks past (lower is better)",
                axis=alt.Axis(format=".0%", tickCount=4), scale=alt.Scale(domain=[0, 1])),
        tooltip=[alt.Tooltip("attack:N", title="Disguise"), alt.Tooltip("System:N"),
                 alt.Tooltip("attack_success_rate:Q", format=".0%", title="Sneaks past"),
                 alt.Tooltip("detected_under_attack:Q", format=".0%", title="Still caught")],
    )
    bars = base.mark_bar(cornerRadiusEnd=4, height=11).encode(
        color=alt.Color("System:N", sort=names, title=None,
                        scale=alt.Scale(domain=names, range=SERIES[:len(names)]),
                        legend=alt.Legend(orient="top", symbolType="square")))
    labels = base.mark_text(align="left", dx=5, fontSize=11, color=INK, font=BODY).encode(
        text=alt.Text("attack_success_rate:Q", format=".0%"))
    chart = alt.layer(bars, labels, data=d).properties(height=13 * len(names) + 8, width=480).facet(
        row=alt.Row("attack:N", sort=attacks, title=None,
                    header=alt.Header(labelAngle=0, labelAlign="left", labelAnchor="start", labelOrient="top",
                                      labelColor=INK, labelFontSize=13, labelFont=BODY, labelPadding=2)))
    return _base(chart.properties(title="Red-team: which disguises fool which system?")).configure_facet(spacing=8)
