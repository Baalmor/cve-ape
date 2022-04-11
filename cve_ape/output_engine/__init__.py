# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import csv
import json
import os
from logging import Logger
from typing import IO, Dict

from .console import output_console
from .util import (
    add_extension_if_not,
    format_output,
    generate_filename,
    get_cve_summary,
)
from ..cve_scanner import CVEData
from ..error_handler import ErrorHandler, ErrorMode
from ..log import LOGGER
from ..util import ProductInfo


def output_json(all_cve_data: Dict[ProductInfo, CVEData], outfile: IO):
    """Output a JSON of CVEs"""
    formatted_output = format_output(all_cve_data)
    json.dump(formatted_output, outfile, indent="    ")


def output_csv(all_cve_data: Dict[ProductInfo, CVEData], outfile):
    """Output a CSV of CVEs"""
    formatted_output = format_output(all_cve_data)
    writer = csv.DictWriter(
        outfile,
        fieldnames=[
            "vendor",
            "product",
            "version",
            "cve_number",
            "severity",
            "score",
            "cvss_version",
            "cvss_vector",
            "paths",
            "remarks",
            "comments",
        ],
    )
    writer.writeheader()
    writer.writerows(formatted_output)


class OutputEngine:
    def __init__(
        self,
        all_cve_data: {},
        filename: str,
        logger: Logger = None,
    ):
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.filename = os.path.abspath(filename) if filename else ""
        self.all_cve_data = all_cve_data

    def output_cves(self, outfile, output_type="console"):
        if output_type == "json":
            output_json(self.all_cve_data, outfile)
        elif output_type == "csv":
            output_csv(self.all_cve_data, outfile)
        else:  # console, or anything else that is unrecognised
            output_console(
                self.all_cve_data
            )

    def output_file(self, output_type="console"):

        """Generate a file for list of CVE"""

        if output_type == "console":
            # short circuit file opening logic if we are actually
            # just writing to stdout
            self.output_cves(self.filename, output_type)
            return

        # Check if we need to generate a filename
        if not self.filename:
            self.filename = generate_filename(output_type)
        else:
            # check and add if the filename doesn't contain extension
            self.filename = add_extension_if_not(self.filename, output_type)

            self.filename = self.check_file_path(self.filename, output_type)

            # try opening that file
            with ErrorHandler(mode=ErrorMode.Ignore) as e:
                with open(self.filename, "w") as f:
                    f.write("testing")
                os.remove(self.filename)
            if e.exit_code:
                self.logger.info(
                    f"Exception {e.exc_val} occurred while writing to the file {self.filename} "
                    "Switching Back to Default Naming Convention"
                )
                self.filename = generate_filename(output_type)

        # call to output_cves
        mode = "w"
        with open(self.filename, mode) as f:
            self.output_cves(f, output_type)

    def check_file_path(self, filepath: str, output_type: str, prefix: str = "output"):
        # check if the file already exists
        if os.path.isfile(filepath):
            self.logger.warning(f"Failed to write at '{filepath}'. File already exists")
            self.logger.info("Generating a new filename with Default Naming Convention")
            filepath = generate_filename(output_type, prefix)

        return filepath

    def check_dir_path(
        self, filepath: str, output_type: str, prefix: str = "intermediate"
    ):

        if os.path.isdir(filepath):
            self.logger.info(
                f"Generating a new filename with Default Naming Convention in directory path {filepath}"
            )
            filename = os.path.basename(generate_filename(output_type, prefix))
            filepath = os.path.join(filepath, filename)

        return filepath
