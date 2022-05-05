import textwrap

import requests
from packaging import version

from cve_ape.log import LOGGER

VERSION: str = "1.0.5"


def check_latest_version():
    """Checks for the latest version available at PyPI."""

    name: str = "cve-ape"
    url: str = f"https://pypi.org/pypi/{name}/json"
    try:
        package_json = requests.get(url).json()
        pypi_version = package_json["info"]["version"]
        if pypi_version != VERSION:
            LOGGER.info(
                f"[bold red]You are running version {VERSION} of {name} but the latest PyPI Version is {pypi_version}.[/]",
                extra={"markup": True},
            )
            if version.parse(VERSION) < version.parse(pypi_version):
                LOGGER.info(
                    "[bold yellow]Alert: We recommend using the latest stable release.[/]",
                    extra={"markup": True},
                )
    except Exception as error:
        LOGGER.warning(
            textwrap.dedent(
                f"""
        -------------------------- Can't check for the latest version ---------------------------
        warning: unable to access 'https://pypi.org/pypi/{name}'
        Exception details: {error}
        Please make sure you have a working internet connection or try again later.
        """
            )
        )
