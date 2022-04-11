import ast
import os
import sys
from io import StringIO

from setuptools.dist import Distribution

with open(os.path.join("cve_ape", "version.py")) as f:
    for line in f:
        if line.startswith("VERSION"):
            VERSION = ast.literal_eval(line.strip().split("=")[-1].strip())
            break


def IS_DEVELOP() -> bool:
    return any(
        list(
            map(
                os.path.isfile,
                list(
                    map(
                        lambda syspath: os.path.join(syspath, "cve-ape.egg-link"),
                        sys.path,
                    )
                ),
            )
        )
    )


def update_egg() -> None:
    with StringIO() as f:
        cwd = os.getcwd()
        os.chdir(os.path.join(os.path.dirname(__file__), ".."))
        sys.stdout = f
        sys.stderr = f
        dist = Distribution(
            dict(
                script_name="setup.py",
                script_args=["egg_info"],
                name="cve-ape",
                version=VERSION,
                entry_points={
                    "console_scripts": [
                        "cve-bin-tool = cve_bin_tool.cli:main",
                    ],
                },
            )
        )
        dist.parse_command_line()
        dist.run_commands()
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        os.chdir(cwd)


if __name__ == "__main__":
    update_egg()
