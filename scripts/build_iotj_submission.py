"""Build the EviGate-APT IEEE IoT-J LaTeX submission package.

The source manuscript remains unchanged. This script converts its Markdown body,
citations, equations, figures, and tables into the official IEEEtran journal
template downloaded through the IEEE Template Selector.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path


BLOCKED_MARKERS = (
    "[UNVERIFIED CITATION — NO ORIGINAL]",
    "[UNVERIFIED CITATION — AI HAS NOT CROSS-CHECKED]",
    "[UNVERIFIED CITATION — NO QUOTE OR PAGE LOCATOR]",
    "<!--anchor:none:",
    "[HIGH-WARN-CLAIM-NOT-SUPPORTED]",
    "[HIGH-WARN-NEGATIVE-CONSTRAINT-VIOLATION",
    "[HIGH-WARN-FABRICATED-REFERENCE]",
    "[HIGH-WARN-CLAIM-AUDIT-ANCHORLESS",
    "[HIGH-WARN-CONSTRAINT-VIOLATION-UNCITED",
    "severity=HIGH-BLOCK",
)


def run_pandoc(pandoc: Path, source: Path, target: Path, lua_filter: Path) -> None:
    command = [
        str(pandoc),
        str(source),
        "--from=markdown+raw_tex+tex_math_dollars",
        "--to=latex",
        "--wrap=none",
        f"--lua-filter={lua_filter}",
        f"--output={target}",
    ]
    subprocess.run(command, check=True)


def extract_metadata(lines: list[str]) -> tuple[str, str, str, list[str]]:
    title = next(line[2:].strip() for line in lines if line.startswith("# "))
    abstract_index = lines.index("## Abstract")
    abstract = next(line.strip() for line in lines[abstract_index + 1 :] if line.strip())
    terms_line = next(line for line in lines if line.startswith("**Index Terms—**"))
    index_terms = terms_line.removeprefix("**Index Terms—**").strip()
    body_start = next(
        index for index, line in enumerate(lines) if re.match(r"##\s+1\.\s+", line)
    )
    body_end = lines.index("## References")
    return title, abstract, index_terms, lines[body_start:body_end]


def strip_heading_number(text: str) -> str:
    return re.sub(r"^\d+(?:\.\d+)*\.?\s+", "", text).strip()


def heading_number(text: str) -> str | None:
    match = re.match(r"^(\d+(?:\.\d+)*)\.?\s+", text)
    return match.group(1) if match else None


def replace_typed_references(text: str) -> str:
    """Convert source-visible typed numbers to stable LaTeX references."""
    range_patterns = (
        (r"\bTables\s+(\d+)[–-](\d+)", "tbl:table", "Tables"),
        (r"\bFigs?\.\s+(\d+)[–-](\d+)", "fig:figure", "Figs."),
        (r"\bFigures\s+(\d+)[–-](\d+)", "fig:figure", "Figs."),
    )
    for pattern, prefix, noun in range_patterns:
        text = re.sub(
            pattern,
            lambda match: (
                rf"{noun}~\ref{{{prefix}{match.group(1)}}}--"
                rf"\ref{{{prefix}{match.group(2)}}}"
            ),
            text,
        )
    text = re.sub(
        r"\bTable\s+(\d+)(?!\.)",
        lambda match: rf"Table~\ref{{tbl:table{match.group(1)}}}",
        text,
    )
    text = re.sub(
        r"\bFig\.\s+(\d+)",
        lambda match: rf"Fig.~\ref{{fig:figure{match.group(1)}}}",
        text,
    )
    text = re.sub(
        r"\bFigure\s+(\d+)",
        lambda match: rf"Fig.~\ref{{fig:figure{match.group(1)}}}",
        text,
    )
    text = re.sub(
        r"\bSection\s+(\d+(?:\.\d+)*)",
        lambda match: rf"Section~\ref{{sec:{match.group(1)}}}",
        text,
    )
    return text


def preprocess_body(lines: list[str]) -> str:
    output: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]

        # The compact manuscript keeps the moved conventional-selector material
        # inside a source-visible LaTeX false block.  Skip that block before
        # Markdown table/figure conversion so hidden captions cannot create
        # duplicate labels in the IEEE source.
        if line.strip() == r"\iffalse":
            index += 1
            while index < len(lines) and lines[index].strip() != r"\fi":
                index += 1
            if index >= len(lines):
                raise ValueError("Unclosed \\iffalse block in manuscript")
            index += 1
            continue

        table_match = re.fullmatch(r"\*\*Table\s+(\d+)\.\s+(.+)\*\*", line)
        if table_match:
            number, caption = table_match.groups()
            output.append(f"Table: {caption} {{#tbl:table{number}}}")
            output.append("")
            index += 1
            continue

        figure_match = re.fullmatch(r"!\[(.*)\]\(([^)]+)\)", line)
        if figure_match:
            lookahead = index + 1
            while lookahead < len(lines) and not lines[lookahead].strip():
                lookahead += 1
            if lookahead >= len(lines):
                raise ValueError(f"Figure at source line {index + 1} has no caption")
            caption_match = re.fullmatch(
                r"\*\*Figure\s+(\d+)\.\s+(.+?)\*\*\s*(.*)",
                lines[lookahead],
            )
            if not caption_match:
                raise ValueError(f"Figure at source line {index + 1} has no IEEE caption")
            number, caption_title, caption_detail = caption_match.groups()
            caption = replace_typed_references(" ".join(
                part.strip() for part in (caption_title, caption_detail) if part.strip()
            ))
            pdf_path = str(Path(figure_match.group(2)).with_suffix(".pdf")).replace("\\", "/")
            output.append(
                f"![{caption}]({pdf_path}){{#fig:figure{number} width=100%}}"
            )
            output.append("")
            index = lookahead + 1
            continue

        heading_two = re.fullmatch(r"##\s+(.+)", line)
        if heading_two:
            raw = heading_two.group(1)
            label = heading_number(raw)
            suffix = f" {{#sec:{label}}}" if label else ""
            output.append(f"# {strip_heading_number(raw)}{suffix}")
            index += 1
            continue

        heading_three = re.fullmatch(r"###\s+(.+)", line)
        if heading_three:
            raw = heading_three.group(1)
            label = heading_number(raw)
            suffix = f" {{#sec:{label}}}" if label else ""
            output.append(f"## {strip_heading_number(raw)}{suffix}")
            index += 1
            continue

        if line.strip() in {r"\[", r"\]"}:
            line = "$$"
        line = re.sub(r"\\\((.+?)\\\)", r"$\1$", line)
        line = replace_typed_references(line)
        line = (
            line.replace("↑", "$\\uparrow$")
            .replace("↓", "$\\downarrow$")
            .replace("±", "$\\pm$")
        )
        output.append(line)
        index += 1

    return "\n".join(output).strip() + "\n"


LONGTABLE_PATTERN = re.compile(
    r"\\begin\{longtable\}\[\]\{@\{\}(.+?)@\{\}\}\n"
    r"\\caption\{(.+?)\}(\\label\{([^}]+)\})?\\tabularnewline\n"
    r"\\toprule\\noalign\{\}\n"
    r"(.+?)\n"
    r"\\midrule\\noalign\{\}\n"
    r"\\endfirsthead\n"
    r"\\toprule\\noalign\{\}\n"
    r".+?\n"
    r"\\midrule\\noalign\{\}\n"
    r"\\endhead\n"
    r"\\bottomrule\\noalign\{\}\n"
    r"\\endlastfoot\n"
    r"(.*?)"
    r"\\end\{longtable\}",
    re.DOTALL,
)


def convert_longtables(latex: str) -> str:
    def replacement(match: re.Match[str]) -> str:
        column_spec = match.group(1)
        caption = match.group(2)
        label = match.group(4) or "tbl:unlabeled"
        header = match.group(5).strip()
        body = match.group(6).strip()
        if label == "tbl:table4":
            # Give method names room while keeping numeric columns compact.
            usable_width = r"(\linewidth - 10\tabcolsep)"
            column_spec = (
                rf">{{\raggedright\arraybackslash}}p{{{usable_width} * \real{{0.30}}}}"
                + rf">{{\raggedleft\arraybackslash}}p{{{usable_width} * \real{{0.14}}}}" * 5
            )
            body = body.replace(
                "Training-calibrated margin + rules",
                "\\midrule\nTraining-calibrated margin + rules",
                1,
            )
        return (
            "\\begin{table*}[!t]\n"
            f"\\caption{{{caption}}}\n"
            f"\\label{{{label}}}\n"
            "\\centering\n"
            "\\footnotesize\n"
            "\\sloppy\n"
            "\\begin{adjustbox}{max width=\\textwidth}\n"
            f"\\begin{{tabular}}{{@{{}}{column_spec}@{{}}}}\n"
            "\\toprule\n"
            f"{header}\n"
            "\\midrule\n"
            f"{body}\n"
            "\\bottomrule\n"
            "\\end{tabular}\n"
            "\\end{adjustbox}\n"
            "\\end{table*}"
        )

    converted, count = LONGTABLE_PATTERN.subn(replacement, latex)
    if count != 4:
        raise ValueError(f"Expected 4 visible main-text tables, converted {count}")
    return converted


def normalize_figures(latex: str) -> str:
    latex = re.sub(r",alt=\{.*?\}(?=\])", "", latex)
    pattern = re.compile(r"\\begin\{figure\}\n(.*?)\\end\{figure\}", re.DOTALL)
    seen: list[int] = []

    def replace_figure(match: re.Match[str]) -> str:
        content = match.group(1)
        label_match = re.search(r"\\label\{fig:figure(\d+)\}", content)
        if not label_match:
            raise ValueError("Figure block has no numbered label")
        number = int(label_match.group(1))
        seen.append(number)
        content = content.replace("width=1\\linewidth", "width=\\textwidth")
        return f"\\begin{{figure*}}[!t]\n{content}\\end{{figure*}}"

    latex = pattern.sub(replace_figure, latex)
    if seen != [1, 2, 3]:
        raise ValueError(f"Expected main-text Figures 1--3; found {seen}")
    return latex


def convert_inline(pandoc: Path, text: str, lua_filter: Path) -> str:
    result = subprocess.run(
        [
            str(pandoc),
            "--from=markdown+raw_tex+tex_math_dollars",
            "--to=latex",
            "--wrap=none",
            f"--lua-filter={lua_filter}",
        ],
        input=text,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


def copy_submission_bibliography(source: Path, target: Path) -> None:
    """Copy the bibliography while preferring compact DOI URLs.

    IEEEtran prints the ``url`` field as the online locator.  Several source
    records include both a DOI and a much longer publisher URL; using the DOI
    resolver preserves the same destination while avoiding unbreakable,
    multi-line reference entries in the two-column layout.
    """

    text = source.read_text(encoding="utf-8")
    blocks = re.split(r"(?=^@)", text, flags=re.MULTILINE)
    normalized: list[str] = []
    for block in blocks:
        doi_match = re.search(r"^\s*doi\s*=\s*\{([^}]+)\}", block, re.MULTILINE | re.IGNORECASE)
        if doi_match:
            doi_url = f"https://doi.org/{doi_match.group(1).strip()}"
            block = re.sub(
                r"(^\s*url\s*=\s*)\{[^}]*\}",
                lambda match: f"{match.group(1)}{{{doi_url}}}",
                block,
                count=1,
                flags=re.MULTILINE | re.IGNORECASE,
            )
        normalized.append(block)
    target.write_text("".join(normalized), encoding="utf-8")


def load_author_metadata(path: Path | None, submission_ready: bool) -> dict[str, str | list[str]]:
    if path is None or not path.exists():
        if submission_ready:
            raise ValueError(
                "Submission-ready build requires --author-metadata with authors, "
                "affiliations, funding, corresponding author, and conflict-of-interest text."
            )
        return {
            "authors_latex": "Anonymous Author(s)",
            "short_author_latex": "Anonymous Author(s)",
            "thanks_latex": [],
            "conflict_of_interest_latex": "",
            "artifact_url": "",
        }

    metadata = json.loads(path.read_text(encoding="utf-8"))
    required = (
        "authors_latex",
        "short_author_latex",
        "funding_latex",
        "affiliations_latex",
        "corresponding_author_latex",
        "conflict_of_interest_latex",
    )
    missing = [key for key in required if not metadata.get(key)]
    if missing:
        raise ValueError(f"Author metadata is incomplete: {missing}")
    artifact_url = str(metadata.get("artifact_url", "")).strip()
    if submission_ready and (
        not artifact_url.startswith("https://")
        or any(marker in artifact_url.lower() for marker in ("example", "placeholder", "replace-", "[", "]"))
        or any(character.isspace() for character in artifact_url)
    ):
        raise ValueError("Submission-ready build requires a verified HTTPS artifact_url in author metadata")
    thanks = [metadata["funding_latex"], *metadata["affiliations_latex"], metadata["corresponding_author_latex"]]
    return {
        "authors_latex": metadata["authors_latex"],
        "short_author_latex": metadata["short_author_latex"],
        "thanks_latex": thanks,
        "conflict_of_interest_latex": metadata["conflict_of_interest_latex"],
        "artifact_url": artifact_url,
    }


def build_tex(
    title: str,
    abstract: str,
    index_terms: str,
    body: str,
    author_metadata: dict[str, str | list[str]],
) -> str:
    thanks = "".join(rf"\thanks{{{item}}}" for item in author_metadata["thanks_latex"])
    authors = f"{author_metadata['authors_latex']}{thanks}"
    coi = str(author_metadata["conflict_of_interest_latex"])
    artifact_url = str(author_metadata.get("artifact_url", ""))
    availability = (
        "Source code, schemas, protocols, aggregate result summaries, and a SHA-256 file manifest "
        + rf"are available at \url{{{artifact_url}}}. The third-party data and per-case evidence packages are not redistributed."
        if artifact_url
        else "Source code, schemas, protocols, aggregate result summaries, and a SHA-256 file manifest "
        "are available from the corresponding author upon reasonable request. "
        "The third-party data and per-case evidence packages are not redistributed."
    )
    coi_block = (
        "\n\n\\noindent\\textbf{Conflict of interest:} " + coi
        if coi
        else ""
    )
    return rf"""\documentclass[lettersize,journal]{{IEEEtran}}
\usepackage[T1]{{fontenc}}
\usepackage{{amsmath,amsfonts}}
\usepackage{{array}}
\usepackage{{booktabs}}
\usepackage{{calc}}
\usepackage{{adjustbox}}
\usepackage[caption=false,font=footnotesize,labelfont=sf,textfont=sf]{{subfig}}
\usepackage{{textcomp}}
\usepackage{{stfloats}}
\usepackage{{url}}
\usepackage{{xurl}}
\usepackage{{graphicx}}
\usepackage{{cite}}
\usepackage{{hyperref}}
\hypersetup{{hidelinks}}
\providecommand{{\tightlist}}{{\setlength{{\itemsep}}{{0pt}}\setlength{{\parskip}}{{0pt}}}}
\hyphenation{{op-tical net-works semi-conduc-tor IEEE-Xplore}}

\begin{{document}}

\bstctlcite{{IEEEtranBSTcontrol}}

\title{{{title}}}

\author{{{authors}}}

\markboth{{IEEE Internet of Things Journal}}{{{author_metadata['short_author_latex']}: EviGate-APT}}

\maketitle

\begin{{abstract}}
{abstract}
\end{{abstract}}

\begin{{IEEEkeywords}}
{index_terms}
\end{{IEEEkeywords}}

{body}

\section*{{Declarations}}
\noindent\textbf{{Data and code availability:}} CICAPT-IIoT is public at its cited provider. {availability}

\noindent\textbf{{Ethics:}} This study analyzes a public cybersecurity testbed dataset and does not involve human participants or animals.
{coi_block}

\section*{{Acknowledgment}}
OpenAI Codex assisted literature searches, analysis-code drafting and checking, English revision, and LaTeX formatting. The authors independently executed and verified all analyses, citations, numerical claims, and text, and retain full responsibility.

\bibliographystyle{{IEEEtran}}
\bibliography{{references}}

\end{{document}}
"""


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=root)
    parser.add_argument(
        "--pandoc",
        type=Path,
        default=root / ".tmp_tools" / "pandoc" / "pandoc-3.11" / "pandoc.exe",
    )
    parser.add_argument(
        "--manuscript",
        type=Path,
        default=root / "paper" / "evigate_apt_main.md",
    )
    parser.add_argument(
        "--author-metadata",
        type=Path,
        default=root / "submission" / "iotj" / "author_metadata.json",
    )
    parser.add_argument("--submission-ready", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = args.root.resolve()
    author_metadata = load_author_metadata(args.author_metadata, args.submission_ready)
    output_dir = root / "submission" / "iotj"
    output_dir.mkdir(parents=True, exist_ok=True)
    manuscript_path = args.manuscript.resolve()
    manuscript_text = manuscript_path.read_text(encoding="utf-8")
    blocked = [marker for marker in BLOCKED_MARKERS if marker in manuscript_text]
    if blocked:
        raise ValueError(f"Cite-time provenance gate failed: {blocked}")

    title, abstract, index_terms, body_lines = extract_metadata(manuscript_text.splitlines())
    # IoT-J states a word limit; use the conventional whitespace-delimited count
    # reported by common manuscript editors so hyphenated technical terms remain
    # single words.
    abstract_words = len(abstract.split())
    if not 150 <= abstract_words <= 250:
        raise ValueError(f"IoT-J abstract must contain 150-250 words; found {abstract_words}")

    official_dir = output_dir / "official-template"
    shutil.copy2(official_dir / "IEEEtran.cls", output_dir / "IEEEtran.cls")
    copy_submission_bibliography(
        root / "references" / "references.bib", output_dir / "references.bib"
    )
    figures_dir = output_dir / "figures"
    figures_dir.mkdir(exist_ok=True)
    for source in sorted((root / "paper" / "figures").glob("figure*.pdf")):
        shutil.copy2(source, figures_dir / source.name)

    preprocessed_path = output_dir / "evigate_apt_iotj.preprocessed.md"
    body_path = output_dir / "evigate_apt_iotj.body.tex"
    lua_filter = output_dir / "tools" / "cite_to_ieee.lua"
    preprocessed_path.write_text(preprocess_body(body_lines), encoding="utf-8")
    run_pandoc(args.pandoc, preprocessed_path, body_path, lua_filter)

    body = body_path.read_text(encoding="utf-8")
    body = convert_longtables(body)
    # The first wide main-text table needs the smaller IEEE script size to
    # avoid unbreakable model names crossing cells.
    body = body.replace("\\footnotesize\n\\sloppy", "\\scriptsize\n\\sloppy", 1)
    body = normalize_figures(body)
    # Pandoc deliberately escapes dollar-delimited math when a closing dollar
    # is followed immediately by a digit (for example ``$\pm$5``).  Normalize
    # these generated forms, and symbols that entered through figure/table
    # captions, to robust LaTeX inline math.
    body = (
        body.replace(r"\$\pm\$", r"\(\pm\)")
        .replace("±", r"\(\pm\)")
        .replace("−", r"\(-\)")
        .replace(r"\textasciitilde{}\ref", r"~\ref")
    )
    body = re.sub(
        r"\\texttt\{([0-9A-F]{64})\}",
        lambda match: rf"\nolinkurl{{{match.group(1)}}}",
        body,
    )
    body = body.replace(
        r"\mathcal{Y}=\{\text{Collection},\text{Discovery},\text{Credential Access},"
        "\n"
        r"\text{Command and Control},\text{Exfiltration}\}.",
        r"\begin{aligned}"
        "\n"
        r"\mathcal{Y}=\{&\text{Collection},\text{Discovery},\text{Credential Access},\\"
        "\n"
        r"&\text{Command and Control},\text{Exfiltration}\}."
        "\n"
        r"\end{aligned}",
    )
    body = body.replace(
        "Edge-intelligent IIoT systems increasingly",
        "\\IEEEPARstart{E}{dge-intelligent} IIoT systems increasingly",
        1,
    )
    body_path.write_text(body, encoding="utf-8")

    inline_title = convert_inline(args.pandoc, title, lua_filter)
    inline_abstract = (
        convert_inline(args.pandoc, abstract, lua_filter)
        .replace("±", r"\(\pm\)")
        .replace("−", r"\(-\)")
    )
    inline_terms = convert_inline(args.pandoc, index_terms, lua_filter)
    tex = build_tex(inline_title, inline_abstract, inline_terms, body, author_metadata)
    (output_dir / "evigate_apt_iotj.tex").write_text(tex, encoding="utf-8")

    print(f"Built {output_dir / 'evigate_apt_iotj.tex'}")
    print(f"Abstract words: {abstract_words}")
    print("Visible tables converted: 4")
    print("Visible figures converted: 3")


if __name__ == "__main__":
    main()
