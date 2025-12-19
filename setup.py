from __future__ import annotations

import re
from pathlib import Path

from setuptools import find_packages, setup


def read_version() -> str:
    init_py = Path(__file__).parent / "titan_decoder" / "__init__.py"
    text = init_py.read_text(encoding="utf-8")
    match = re.search(r"^__version__\s*=\s*\"([^\"]+)\"\s*$", text, re.M)
    if not match:
        raise RuntimeError("Unable to find __version__ in titan_decoder/__init__.py")
    return match.group(1)


with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="titan-decoder",
    version=read_version(),
    author="PragmaConflux",
    author_email="pragmaconflux@users.noreply.github.com",
    description="Advanced payload decoding and analysis engine for cybersecurity",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pragmaconflux/titan1",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "titan-decoder=titan_decoder.cli:main",
        ],
    },
    install_requires=[
        # Add dependencies here
    ],
    extras_require={
        "dev": ["pytest", "ruff"],
    },
)
