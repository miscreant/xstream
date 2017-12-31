#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

requirements = []
test_requirements = []

setup(
    name="xstream",
    version="0.0.0",
    description="Public key encryption system combining X25519 Diffie-Hellman with the STREAM construction",
    long_description=(
        "XSTREAM combines the X25519 Elliptic Curve Diffie-Hellman function"
        "with HKDF and the STREAM construction for streaming authenticated"
        "encryption. The result is an easy-to-use public key cryptosystem."
    ),
    author="Tony Arcieri",
    author_email="bascule@gmail.com",
    url="https://github.com/miscreant/xstream",
    packages=find_packages(exclude=["tests"]),
    package_dir={"xstream": "xstream"},
    include_package_data=True,
    install_requires=["cryptography>=2.0","miscreant>=0.3"],
    license="MIT license",
    zip_safe=False,
    keywords=["cryptography", "security"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
    ],
    test_suite="tests",
    tests_require=[]
)
