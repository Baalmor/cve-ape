import csv
import re
from collections import defaultdict
from logging import Logger
from os.path import dirname, getsize, isfile, join
from csv import DictReader, reader, unix_dialect

from cve_ape.cvedb import CVEDB
from cve_ape.error_handler import (
    EmptyTxtError,
    ErrorHandler,
    ErrorMode,
)
from cve_ape.log import LOGGER
from cve_ape.util import ProductInfo, Remarks

ROOT_PATH = join(dirname(__file__), "..")


class PackageListParser:
    def __init__(
        self, input_file: str, logger: Logger = None, csv_format:str = None, csv_delimiter:str = ";", error_mode=ErrorMode.TruncTrace
    ) -> None:
        self.input_file = input_file
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.error_mode = error_mode
        self.csv_format = csv_format
        self.csv_delimiter = csv_delimiter
        self.parsed_data_without_vendor = defaultdict(dict)
        self.parsed_data_with_vendor = defaultdict(dict)
        self.package_names_known = []
        self.package_names_unknown = []

    def process_file(self, input_file):
        packages = []
        with open(input_file) as req:
            lines = req.readlines()
        parser_re = re.compile(r"^(.*?)\-(?=(?:[0-9]+\.){0,}[0-9]+(?:-[a-z]+)?)(.*?)$")
        for line in lines:
            parse = parser_re.search(re.split("\n", line)[0])
            if parse is not None:
                packages.append({"name": parse[1], "version": parse[2]})
            else:
                self.logger.warning(f"Did not parsed: {line}")
        return packages

    def process_file_csv(self, input_file, fields):
        packages = []
        dialect = unix_dialect
        dialect.delimiter = self.csv_delimiter
        with open(input_file) as read_obj:
            if fields[0].isnumeric() and fields[1].isnumeric():
                rd = reader(read_obj, dialect=dialect)
                list_out = list(rd)
                for line in list_out:
                    if len(line) >= 2:
                        packages.append({
                            "name": line[int(fields[0])],
                            "version": line[int(fields[1])]
                            })
            else:
                rd = DictReader(read_obj, dialect=dialect)
                list_out = list(rd)
                for line in list_out:
                    keys = line.keys()
                    if fields[0] in keys and fields[1] in keys:
                        packages.append({"name": line[fields[0]], "version": line[fields[1]]})
        return packages

    def parse_list(self):
        input_file = self.input_file
        file_type = self.check_file()
        if file_type == 'csv':
            if self.csv_format is not None:
                fields = self.csv_format.split(",")
                if len(fields) != 2:
                    self.logger.warning("CSV fields were not recognized. This is what I get: {}. "
                                      "Trying to use a default settings.".format(fields))
                    packages = self.process_file_csv(input_file, ("Name", "Version"))
                else:
                    packages = self.process_file_csv(input_file, tuple(fields))
            else:
                packages = self.process_file_csv(input_file, ("Name", "Version"))
        else:
            if self.csv_format is not None:
                self.logger.warning("CSV file is not recognized. Trying to process as a txt file.")
            packages = self.process_file(input_file)
        cve_db = CVEDB()
        self.package_names_known, self.package_names_unknown = cve_db.get_packages_from_pkglist(
            packages
        )
        return self.package_names_known

    def parse_data(self):
        for row in self.package_names_known:
            product_info = ProductInfo(
                row["vendor"], row["name"].lower(), row["version"]
            )
            self.parsed_data_with_vendor[product_info][
                row.get("cve_number", "").strip() or "default"
            ] = {
                "remarks": Remarks.NewFound,
                "comments": row.get("comments", "").strip(),
                "severity": row.get("severity", "").strip(),
            }
            self.parsed_data_with_vendor[product_info]["paths"] = {""}

    def check_file(self):
        input_file = self.input_file
        error_mode = self.error_mode

        if not isfile(input_file):
            with ErrorHandler(mode=error_mode):
                raise FileNotFoundError(input_file)

        if getsize(input_file) == 0:
            with ErrorHandler(mode=error_mode):
                raise EmptyTxtError(input_file)

        with open(input_file) as f:
            first_line = f.readline()
            if re.match(r'^[^\;\,]+$', first_line):
                return 'txt'
            else:
                return 'csv'
