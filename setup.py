import ast
import os

from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as f:
    readme = f.read()

with open("requirements.txt", encoding="utf-8") as f:
    requirements = f.read().split("\n")

with open(os.path.join("cve_ape", "version.py")) as f:
    for line in f:
        if line.startswith("VERSION"):
            VERSION = ast.literal_eval(line.strip().split("=")[-1].strip())
            break

setup_kwargs = dict(
    name="cve-ape",
    version=VERSION,
    description="CVE scanner which can process pkglists",
    long_description=readme,
    long_description_content_type="text/markdown",
    author="Alexey Perepechko",
    author_email="alexey.perepechko@gmail.com",
    maintainer="Alexey Perepechko",
    maintainer_email="alexey.perepechko@gmail.com",
    url="https://github.com/Baalmor/cve-ape",
    license="MIT",
    keywords=["security", "tools", "CVE"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
    install_requires=requirements,
    packages=find_packages(include=['cve_ape','cve_ape.*']),
    project_urls={
        'Bug Reports': 'https://github.com/Baalmor/cve-ape/issues',
        'Source': 'https://github.com/Baalmor/cve-ape',
    },
    entry_points={
        "console_scripts": [
            "cve-ape = cve_ape.cli:main",
        ],
    },
)

setup(**setup_kwargs)