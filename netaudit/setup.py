#!/usr/bin/env python3
"""
CRYPTSK NetAudit - Setup Script
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="netaudit",
    version="1.0.0",
    author="CRYPTSK",
    description="Linux Network Infrastructure Audit Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cryptsk/netaudit",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.11",
    install_requires=[
        "fastapi>=0.109.0",
        "uvicorn>=0.27.0",
        "typer>=0.9.0",
        "rich>=13.7.0",
        "pydantic>=2.5.0",
    ],
    entry_points={
        "console_scripts": [
            "netaudit=cli.main:app",
        ],
    },
)
