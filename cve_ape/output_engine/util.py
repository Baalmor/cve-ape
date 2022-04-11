import os
from collections import defaultdict
from datetime import datetime
from typing import DefaultDict, Dict, List

from ..util import CVE, Remarks


def get_cve_summary(all_cve_data):
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for cve_data in all_cve_data.values():
        for s in summary.keys():
            summary[s] += 1 if cve_data["severity"] == s else 0
    return summary


def generate_filename(extension: str, prefix: str = "output") -> str:
    now = datetime.now().strftime("%Y-%m-%d.%H-%M-%S")

    filename = os.path.abspath(
        os.path.join(os.getcwd(), f"{prefix}.cve-bin-tool.{now}.{extension}")
    )

    return filename


def format_output(all_cve_data: []) -> List[Dict[str, str]]:
    formatted_output = []
    for product_info, cve_data in all_cve_data.items():
        for cve in cve_data["cves"]:
            formatted_output.append(
                {
                    "vendor": product_info.vendor,
                    "product": product_info.product,
                    "version": product_info.version,
                    "cve_number": cve.cve_number,
                    "severity": cve.severity,
                    "score": str(cve.score),
                    "cvss_version": str(cve.cvss_version),
                    "cvss_vector": cve.cvss_vector,
                    "paths": ", ".join(cve_data["paths"]),
                    "remarks": cve.remarks.name,
                    "comments": cve.comments,
                }
            )

    return formatted_output


def add_extension_if_not(filename: str, output_type: str) -> str:
    if not filename.endswith(f".{output_type}"):
        updated_filename = f"{filename}.{output_type}"
        return updated_filename
    else:
        return filename


def group_cve_by_remark(
    cve_by_product: List[CVE],
) -> DefaultDict[Remarks, List[Dict[str, str]]]:
    cve_by_remarks: DefaultDict[Remarks, List[Dict[str, str]]] = defaultdict(list)
    for cve in cve_by_product:
        cve_by_remarks[cve.remarks].append(
            {
                "cve_number": cve.cve_number,
                "severity": cve.severity,
                "description": cve.description,
                "vector": cve.cvss_vector,
            }
        )
    return cve_by_remarks
