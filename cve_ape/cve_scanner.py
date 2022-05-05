import os
import re
import sqlite3
import sys
from collections import defaultdict
from logging import Logger
from string import ascii_lowercase
from typing import DefaultDict, Dict

from packaging.version import Version, LegacyVersion, InvalidVersion
from rich.console import Console

from cve_ape.cvedb import DBNAME, DISK_LOCATION_DEFAULT, CVEDB
from cve_ape.error_handler import ErrorMode
from cve_ape.log import LOGGER
from cve_ape.theme import cve_theme
from cve_ape.util import CVEData, ProductInfo, VersionInfo

ALPHA_TO_NUM: Dict[str, int] = dict(zip(ascii_lowercase, range(26)))
re_openssllike = re.compile(r'^((\d+(\.|)){3,})(.*)$')
re_digit = re.compile(r'\d+')


def break_openssllike_version(version):
    v = re.search(re_openssllike, version)
    if v:
        version = v.group(1)
        tail = v.group(4)
        dk = re.findall(re_digit, tail)
        if tail.isalpha():
            version = "{}.{}".format(version, ALPHA_TO_NUM[tail])
        elif dk:
            for d in dk:
                version = "{}.{}".format(version, d)
    return Version(version)


def ver(version):
    try:
        v = Version(version)
    except InvalidVersion:
        v = LegacyVersion(version)
    try:
        if re.search('[a-zA-Z]', v.base_version):
            v = break_openssllike_version(version)
    except:
        return Version("0")
    return v


def version_range(version, start_including, start_excluding, end_including, end_excluding):
    if start_including and end_including:
        return True if start_including <= version <= end_including else False
    if start_including and end_excluding:
        return True if start_including <= version < end_excluding else False
    if start_excluding and end_including:
        return True if start_excluding < version <= end_including else False
    if start_excluding and end_excluding:
        return True if start_excluding < version < end_excluding else False
    if start_including:
        return True if start_including <= version else False
    if start_excluding:
        return True if start_excluding < version else False
    if end_including:
        return True if end_including >= version else False
    if end_excluding:
        return True if end_excluding > version else False
    return False


class CVEScanner:
    """
    This class is for reading CVEs from the database
    """

    products_with_cve: int
    products_without_cve: int
    all_cve_data: DefaultDict[ProductInfo, CVEData]
    all_cve_version_info: Dict[str, VersionInfo]

    RANGE_UNSET: str = ""
    dbname: str = os.path.join(DISK_LOCATION_DEFAULT, DBNAME)
    CONSOLE: Console = Console(file=sys.stderr, theme=cve_theme)
    ALPHA_TO_NUM: Dict[str, int] = dict(zip(ascii_lowercase, range(26)))

    def __init__(
            self,
            score: int = 0,
            logger: Logger = None,
            error_mode: ErrorMode = ErrorMode.TruncTrace,
    ):
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.error_mode = error_mode
        self.score = score
        self.products_with_cve = 0
        self.products_without_cve = 0
        self.all_cve_data = defaultdict(CVEData)
        self.all_cve_version_info = dict()

    def get_cves(self, packages):
        cve_db = CVEDB()
        cve_list = cve_db.get_cves_for_packages(packages)
        cve_report_list = {}

        for cve_bind_product in cve_list:
            cve_number = cve_bind_product["cve_number"]
            version_start_including = None if cve_bind_product["versionStartIncluding"] == "" \
                else ver(cve_bind_product["versionStartIncluding"])

            version_end_including = None if cve_bind_product["versionEndIncluding"] == "" \
                else ver(cve_bind_product["versionEndIncluding"])

            version_start_excluding = None if cve_bind_product["versionStartExcluding"] == "" \
                else ver(cve_bind_product["versionStartExcluding"])

            version_end_excluding = None if cve_bind_product["versionEndExcluding"] == "" \
                else ver(cve_bind_product["versionEndExcluding"])

            version = "*" if cve_bind_product["version"] == "*" else ver(cve_bind_product["version"])

            package_version = ver(cve_bind_product["pkglist_package_version"])

            passed = False
            conditional = False

            if version == "*":
                # including
                passed = version_range(package_version,
                                       version_start_including,
                                       version_start_excluding,
                                       version_end_including,
                                       version_end_excluding)
            elif version == package_version:
                passed = True
            elif version.base_version == package_version.base_version:
                passed = True  # conditional true
                conditional = True

            if passed:
                v = VersionInfo(
                    version_start_including,
                    version_start_excluding,
                    version_end_including,
                    version_end_excluding,
                    conditional)
                cve_report_list[cve_number] = {"pkglist_package_version": package_version.public,
                                               "pkglist_package_name": cve_bind_product["package"],
                                               "pkglist_package_vendor": cve_bind_product["vendor"],
                                               "version_range": v}

        # Go through and get all the severities
        details = cve_db.get_cve_info_bulk(list(cve_report_list.keys()))
        cve_results = {}
        for k in cve_report_list.keys():
                if k in details:
                    cve_results[k] = {**cve_report_list[k], **details[k]}
        if cve_results.keys():
            for k in cve_results.keys():
                c = cve_results[k]
                self.logger.debug(
                    ' CVE in {}.{} v{} - {}:{}'.format(c["pkglist_package_name"],
                                                       c["pkglist_package_vendor"],
                                                       c["pkglist_package_version"],
                                                       k,
                                                       c["severity"])
                )
        return cve_results

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
