"""Setup module for zigpy-deconz."""

import os

from setuptools import find_packages, setup

import zigpy_deconz

this_directory = os.path.join(os.path.abspath(os.path.dirname(__file__)))
with open(os.path.join(this_directory, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="zigpy-deconz",
    version=zigpy_deconz.__version__,
    description="A library which communicates with Deconz radios for zigpy",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="http://github.com/zigpy/zigpy-deconz",
    author="Daniel Schmidt",
    author_email="schmidt.d@aon.at",
    license="GPL-3.0",
    packages=find_packages(exclude=["tests"]),
    install_requires=["pyserial-asyncio", "zigpy>=0.40.0"],
    tests_require=["pytest", "pytest-asyncio", "asynctest"],
)
