"""Setup module for zigpy-deconz"""

from setuptools import find_packages, setup

import zigpy_deconz

setup(
    name="zigpy-deconz",
    version=zigpy_deconz.__version__,
    description="A library which communicates with Deconz radios for zigpy",
    url="http://github.com/zigpy/zigpy-deconz",
    author="Daniel Schmidt",
    author_email="schmidt.d@aon.at",
    license="GPL-3.0",
    packages=find_packages(exclude=["*.tests"]),
    install_requires=["pyserial-asyncio", "zigpy-homeassistant>=0.17.0"],
    tests_require=["pytest", "pytest-asyncio", "asynctest"],
)
