"""Setup module for zigbpy-xbee"""

from setuptools import find_packages, setup

setup(
    name="zigpy-deconz",
    version="0.1.1",
    description="A library which communicates with Deconz radios for zigpy",
    url="http://github.com/zigpy/zigpy-deconz",
    author="Daniel Schmidt",
    author_email="schmidt.d@aon.at",
    license="GPL-3.0",
    packages=find_packages(exclude=['*.tests']),
    install_requires=[
        'pyserial-asyncio',
        'zigpy-homeassistant',
    ],
    tests_require=[
        'pytest',
    ],
)
