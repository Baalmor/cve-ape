import argparse
import logging
import os
import sys
import textwrap
import time
from collections import ChainMap

from cve_ape.cve_scanner import CVEScanner
from cve_ape.cvedb import CVEDB, OLD_CACHE_DIR, DISK_LOCATION_DEFAULT
from cve_ape.error_handler import (
    CVEDataMissing,
    EmptyCache,
    ErrorHandler,
    ErrorMode,
    InsufficientArgs,
    excepthook,
)
from cve_ape.log import LOGGER
from cve_ape.output_engine import OutputEngine
from cve_ape.package_list_parser import PackageListParser

if sys.version_info >= (3, 8):
    pass
else:
    pass

sys.excepthook = excepthook  # Always install excepthook for entrypoint module.


class StringToListAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        values = list(map(lambda val: val.strip(), values.split(",")))
        setattr(namespace, self.dest, values)


def main(argv=None):
    """Scan a binary file for certain open source libraries that may have CVEs"""
    argv = argv or sys.argv

    # Reset logger level to info
    LOGGER.setLevel(logging.INFO)

    parser = argparse.ArgumentParser(
        prog="cve-ape",
        description=textwrap.dedent(
            """
            """
        ),
        epilog=textwrap.fill(
            f''
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    nvd_database_group = parser.add_argument_group(
        "CVE Data Download", "Arguments related to NVD Database and Cache Configuration"
    )
    nvd_database_group.add_argument(
        "-n",
        "--nvd",
        action="store",
        choices=["api", "json"],
        help="choose method for getting CVE lists from NVD",
        default="api",
    )
    nvd_database_group.add_argument(
        "-u",
        "--update",
        action="store",
        choices=["now", "daily", "never", "latest"],
        help="update schedule for NVD database (default: daily)",
        default="daily",
    )
    nvd_database_group.add_argument(
        "--cache-dir",
        action="store",
        default=DISK_LOCATION_DEFAULT,
        help="specify the NVD database and cache location (default: ~/.cache/cve-ape)",
    )
    nvd_database_group.add_argument(
        "--nvd-api-key",
        action="store",
        default="",
        help="specify NVD API key (used to improve NVD rate limit)",
    )

    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "-L", "--package-list", action="store", default="", help="provide a package list."
    )
    input_group.add_argument(
        "-C", "--csv-format", action="store", default="", help="comma separated headers if file is a CSV, "
                                                               "or comma separated column numbers started from 0 where the "
                                                               "first is a package and the second is a version."
    )

    input_group.add_argument(
        "-d", "--csv-delimiter", action="store", default=";", help="a delimiter used in the csv file. Default: \";\""
    )

    input_group.add_argument(
        "--no-scan", action="store_true", default=False, help="don't do scanning. Just an update."
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress output",
        default=False,
    )
    output_group.add_argument(
        "-l",
        "--log",
        help="log level (default: info)",
        dest="log_level",
        action="store",
        choices=["debug", "info", "warning", "error", "critical"],
        default="info",
    )
    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        help="provide output filename (default: output to stdout)",
        default="",
    )

    output_group.add_argument(
        "-f",
        "--format",
        action="store",
        choices=["csv", "json", "console"],
        help="update output format (default: console)",
        default="console",
    )
    output_group.add_argument(
        "-c",
        "--cvss",
        action="store",
        help="minimum CVSS score (as integer in range 0 to 10) to report (default: 0)",
        default=0,
    )
    output_group.add_argument(
        "-S",
        "--severity",
        action="store",
        choices=["low", "medium", "high", "critical"],
        help="minimum CVE severity to report (default: low)",
        default="low",
    )
    parser.add_argument(
        "-e",
        "--exclude",
        action=StringToListAction,
        help="Line separated Exclude package list. It shell be the same format as an inclusion list."
             " e.g. if you use CSV to test, you should use CSV for exclusion too",
        default=[],
    )
    parser.add_argument(
        "--disable-version-check",
        action="store_true",
        help="skips checking for a new version",
        default=False,
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="operate in offline mode",
        default=False,
    )

    with ErrorHandler(mode=ErrorMode.NoTrace):
        raw_args = parser.parse_args(argv[1:])
        args = {key: value for key, value in vars(raw_args).items() if value}
        defaults = {key: parser.get_default(key) for key in vars(raw_args)}

    configs = {}

    args = ChainMap(args, configs, defaults)

    # logging and error related settings
    if args["log_level"]:
        LOGGER.setLevel(args["log_level"].upper())

    if args["quiet"]:
        LOGGER.setLevel(logging.CRITICAL)

    if 0 < LOGGER.level <= 10:
        error_mode = ErrorMode.FullTrace
    elif LOGGER.level >= 50:
        error_mode = ErrorMode.NoTrace
    else:
        error_mode = ErrorMode.TruncTrace

    # once logging is set, we can output the version and NVD notice
    LOGGER.info(f"Package list CVE search tool v1.0")
    LOGGER.info(
        "This product uses the NVD API but is not endorsed or certified by the NVD."
    )

    # If NVD API key is not set, check for environment variable (e.g. GitHub Secrets)
    if not args["nvd_api_key"] and os.getenv("nvd_api_key"):
        args["nvd_api_key"] = os.getenv("nvd_api_key")

    # Also try the uppercase env variable, in case people prefer those
    if not args["nvd_api_key"] and os.getenv("NVD_API_KEY"):
        args["nvd_api_key"] = os.getenv("NVD_API_KEY")

    # If you're not using an NVD key, let you know how to get one
    if not args["nvd_api_key"] and not args["offline"]:
        LOGGER.info("Not using an NVD API key. Your access may be rate limited by NVD.")
        LOGGER.info(
            "Get an NVD API key here: https://nvd.nist.gov/developers/request-an-api-key"
        )

    # CSVScanner related settings
    score = 0
    if args["severity"]:
        # Set minimum CVSS score based on severity
        cvss_score = {"low": 0, "medium": 4, "high": 7, "critical": 9}
        score = cvss_score[args["severity"]]
    if int(args["cvss"]) > 0:
        score = int(args["cvss"])

    # Offline processing
    if args["offline"]:
        # Override version check and database update arguments
        version_check = True
        db_update = "never"
    else:
        version_check = args["disable_version_check"]
        db_update = args["update"]

    output_format = args["format"]

    # Database update related settings
    # Connect to the database
    cvedb_orig = CVEDB(
        cachedir=os.path.expanduser(args["cache_dir"]),
        version_check=not version_check,
        error_mode=error_mode,
        nvd_type=args["nvd"],
        incremental_update=True if db_update == "latest" and args["nvd"] else False,
        nvd_api_key=args["nvd_api_key"],
    )

    # if OLD_CACHE_DIR (from cvedb.py) exists, print warning
    if os.path.exists(OLD_CACHE_DIR):
        LOGGER.warning(
            f"Obsolete cache dir {OLD_CACHE_DIR} is no longer needed and can be removed."
        )

    # Check database exists if operating in offline mode.
    if args["offline"] and not cvedb_orig.check_db_exists():
        LOGGER.critical("Database does not exist. Make sure, that you've run the tool at least on online.")
        return -1

    # Clear data if -u now is set
    if db_update == "now":
        cvedb_orig.clear_cached_data()

    if db_update == "latest":
        cvedb_orig.refresh_cache_and_update_db()

    # update db if needed
    if db_update != "never":
        cvedb_orig.get_cvelist_if_stale()
    else:
        if args["nvd"] == "json":
            LOGGER.warning("Not verifying CVE DB cache")
            cvedb_orig.get_db_update_date()
            if not cvedb_orig.nvd_years():
                with ErrorHandler(mode=error_mode, logger=LOGGER):
                    raise EmptyCache(cvedb_orig.cachedir)

    # CVE Database validation
    if not cvedb_orig.check_cve_entries():
        with ErrorHandler(mode=error_mode, logger=LOGGER):
            raise CVEDataMissing("No data in CVE Database")

    # Report time of last database update
    db_date = time.strftime(
        "%d %B %Y at %H:%M:%S", time.localtime(cvedb_orig.get_db_update_date())
    )
    LOGGER.info(f"CVE database last updated on {db_date}")

    cvedb_orig.remove_cache_backup()

    if args["no_scan"]:
        if not args["quiet"]:
            LOGGER.info("No scan is selected. Gracefully shutting down.")
        return 0

    # Input validation
    if (
        not args["package_list"]
    ):
        parser.print_usage()
        with ErrorHandler(logger=LOGGER, mode=ErrorMode.NoTrace):
            raise InsufficientArgs(
                "A package list file required"
            )

    with CVEScanner(score=score) as cve_scanner:
        # Package List parsing
        if args["package_list"]:
            if args["csv_format"]:
                package_list = PackageListParser(
                    args["package_list"], csv_format=args["csv_format"], csv_delimiter=args["csv_delimiter"], error_mode=error_mode
                )
            else:
                package_list = PackageListParser(
                    args["package_list"], error_mode=error_mode
                )
            parsed_data = package_list.parse_list()
            cves = cve_scanner.get_cves(parsed_data)

        LOGGER.info("")
        LOGGER.info("Overall CVE summary: ")

        if cves:
            LOGGER.info(f"Known CVEs: {len(cves.keys())}:")

            # Creates an Object for OutputEngine
            output = OutputEngine(
                all_cve_data=cves,
                filename=args["output_file"],
            )

            if not args["quiet"]:
                output.output_file(output_format)

        # If no cves found, then the program exits cleanly (0 exit)
        if cve_scanner.products_with_cve == 0:
            return 0

        # if some cves are found, return with exit code 1
        # Previously this returned a number of CVEs found, but that can
        # exceed expected return value range.
        if cve_scanner.products_with_cve > 0:
            return 1

        # If somehow we got negative numbers of cves something has gone
        # horribly wrong.  Since return code 2 is used by argparse, use 3
        return 3


if __name__ == "__main__":
    if os.getenv("NO_EXIT_CVE_NUM"):
        main()
    else:
        sys.exit(main())
