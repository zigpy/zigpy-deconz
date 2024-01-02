# zigpy-deconz

[![Build Status](https://travis-ci.org/zigpy/zigpy-deconz.svg?branch=master)](https://travis-ci.org/zigpy/zigpy-deconz)
[![Coverage](https://coveralls.io/repos/github/zigpy/zigpy-deconz/badge.svg?branch=master)](https://coveralls.io/github/zigpy/zigpy-deconz?branch=master)

[zigpy-deconz](https://github.com/zigpy/zigpy-deconz) is a Python 3 implementation for the [Zigpy](https://github.com/zigpy/) project to implement [deCONZ](https://www.dresden-elektronik.de/funktechnik/products/software/pc/deconz/) based [Zigbee](https://www.zigbee.org) radio devices.

The goal of this project to add native support for the Dresden-Elektronik/Phoscon deCONZ based ZigBee modules in Home Assistant via [zigpy](https://github.com/zigpy/).

This library uses the deCONZ serial protocol for communicating with [ConBee](https://phoscon.de/en/conbee), [ConBee II (ConBee 2)](https://phoscon.de/en/conbee2), [ConBee III (ConBee 3)](https://phoscon.de/en/conbee3), [RaspBee](https://phoscon.de/en/raspbee), and [RaspBee II (RaspBee 2)](https://phoscon.de/en/raspbee2) adapters from [Dresden-Elektronik](https://github.com/dresden-elektronik/)/[Phoscon](https://phoscon.de).

# Releases via PyPI

Tagged versions are also released via PyPI

- https://pypi.org/project/zigpy-deconz/
- https://pypi.org/project/zigpy-deconz/#history
- https://pypi.org/project/zigpy-deconz/#files

# External documentation and reference

Note! Latest official documentation for the deCONZ serial protocol can currently be obtained by following link in Dresden-Elektronik GitHub repository here:

- https://github.com/dresden-elektronik/deconz-serial-protocol
- https://github.com/dresden-elektronik/deconz-serial-protocol/issues/2

For reference, here is a list of unrelated projects that also use the same deCONZ serial protocol for other implementations:

- https://github.com/Equidamoid/pyconz/commits/master
- https://github.com/mozilla-iot/deconz-api
- https://github.com/adetante/deconz-sp
- https://github.com/frederic34/plugin-nodeBee

# How to contribute

If you are looking to make a contribution to this project we suggest that you follow the steps in these guides:

- https://github.com/firstcontributions/first-contributions/blob/master/README.md
- https://github.com/firstcontributions/first-contributions/blob/master/github-desktop-tutorial.md

Some developers might also be interested in receiving donations in the form of hardware such as Zigbee modules or devices, and even if such donations are most often donated with no strings attached it could in many cases help the developers motivation and indirect improve the development of this project.
