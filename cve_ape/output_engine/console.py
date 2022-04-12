import textwrap
from collections import defaultdict
from datetime import datetime

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .util import get_cve_summary
from ..linkify import linkify_cve
from ..theme import cve_theme
from ..util import VersionInfo

SUMMARY_COLOR = {
    "CRITICAL": "red",
    "HIGH": "blue",
    "MEDIUM": "yellow",
    "LOW": "green",
}

SUMMARY_ORDER = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
}


def format_version_range(version_info: VersionInfo) -> str:
    (start_including, start_excluding, end_including, end_excluding, is_conditional) = version_info
    if start_including and end_including:
        return f"[{start_including} - {end_including}]"
    if start_including and end_excluding:
        return f"[{start_including} - {end_excluding})"
    if start_excluding and end_including:
        return f"({start_excluding} - {end_including}]"
    if start_excluding and end_excluding:
        return f"({start_excluding} - {end_excluding})"
    if start_including:
        return f">= {start_including}"
    if start_excluding:
        return f"> {start_excluding}"
    if end_including:
        return f"<= {end_including}"
    if end_excluding:
        return f"< {end_excluding}"
    return "-"


def score_colors(input_score):
    if type(input_score) == int or type(input_score) == float:
        if 0 <= input_score < 3.9:
            return "white"
        elif 3.9 <= input_score < 5.9:
            return "yellow"
        elif 5.9 <= input_score < 7.9:
            return "red"
        elif input_score >= 7.9:
            return "black"
    else:
        try:
            return SUMMARY_COLOR[input_score]
        except:
            return "white"


def output_console(
        all_cve_data: {},
        console=Console(theme=cve_theme),
):
    console._width = 120
    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

    console.print(
        Markdown(
            textwrap.dedent(
                f"""
                Report Generated: {now}
                """
            )
        )
    )

    # Create table instance for CVE Summary
    table = Table()
    # Add Head Columns to the Table
    table.add_column("Severity")
    table.add_column("Count")
    summary = get_cve_summary(all_cve_data)

    for severity, count in summary.items():
        color = SUMMARY_COLOR[severity]
        cells = [
            Text.styled(severity, color),
            Text.styled(str(count), color),
        ]
        table.add_row(*cells)
    # Print the table to the console
    console.print(Panel("CVE SUMMARY", expand=False))
    console.print(table)

    cve_by_score = defaultdict(list)
    # group cve_data by its remarks
    for cve, cve_data in all_cve_data.items():
        key = (
            SUMMARY_ORDER[cve_data["severity"]],
            cve_data["severity"]
        )
        cve_by_score[key].append(
            {
                "vendor": cve_data["pkglist_package_vendor"],
                "product": cve_data["pkglist_package_name"],
                "version": cve_data["pkglist_package_version"],
                "cve_number": cve_data["cve_number"],
                "severity": cve_data["severity"],
                "score": cve_data["score"],
                "cvss_version": cve_data["cvss_version"],
                "version_range": cve_data["version_range"]
            }
        )

    for key in sorted(cve_by_score):
        score = key[1]
        color = score_colors(score)
        # table instance
        table = Table()

        # Add Head Columns to the Table
        table.add_column("Vendor")
        table.add_column("Product")
        table.add_column("Version")
        table.add_column("CVE Number")
        table.add_column("Severity")
        table.add_column("Score (CVSS Version)")
        table.add_column("Affected versions")
        # table.add_column("CVSS Version")

        for cve_data in cve_by_score[key]:
            color = cve_data["severity"].lower()
            cells = [
                Text.styled(cve_data["vendor"], color),
                Text.styled(cve_data["product"], color),
                Text.styled(cve_data["version"], color),
                linkify_cve(Text.styled(cve_data["cve_number"], color)),
                Text.styled(cve_data["severity"], color),
                Text.styled(
                    str(cve_data["score"])
                    + " (v"
                    + str(cve_data["cvss_version"])
                    + ")",
                    color,
                ),
                Text.styled(format_version_range(cve_data["version_range"]), color),
            ]
            table.add_row(*cells)
        # Print the table to the console
        console.print(table)
        for cve_data in cve_by_score[key]:
            if "*" in cve_data["vendor"]:
                console.print("* vendors guessed by the tool")
                break
