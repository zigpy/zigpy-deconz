# zigpy-deconz

[![Build Status](https://travis-ci.org/zigpy/zigpy-deconz.svg?branch=master)](https://travis-ci.org/zigpy/zigpy-deconz)
[![Coverage](https://coveralls.io/repos/github/zigpy/zigpy-deconz/badge.svg?branch=master)](https://coveralls.io/github/zigpy/zigpy-deconz?branch=master)

[zigpy-deconz](https://github.com/zigpy/zigpy-deconz) is a Python 3 implementation for the [Zigpy](https://github.com/zigpy/) project to implement [deCONZ](https://www.dresden-elektronik.de/funktechnik/products/software/pc/deconz/) based [Zigbee](https://www.zigbee.org) radio devices.

The goal of this project to add native support for the Dresden-Elektronik deCONZ based ZigBee modules in Home Assistant via [Zigpy](https://github.com/zigpy/).

This library uses the deCONZ serial protocol for communicating with [ConBee](https://www.dresden-elektronik.de/conbee/), [ConBee II (ConBee 2)](https://shop.dresden-elektronik.de/conbee-2.html), and [RaspBee](https://www.dresden-elektronik.de/raspbee/) adapters from [Dresden-Elektronik](https://github.com/dresden-elektronik/).

# Releases via PyPI
Tagged versions are also released via PyPI

- https://pypi.org/project/zigpy-deconz/
- https://pypi.org/project/zigpy-deconz/#history
- https://pypi.org/project/zigpy-deconz/#files

# External documentation and reference

Note! Latest official documentation for the deCONZ serial protocol can currently be obtained by contacting Dresden-Elektronik employees via GitHub here
-  https://github.com/dresden-elektronik/deconz-rest-plugin/issues/158

For reference, here is a list of unrelated projects that also use the same deCONZ serial protocol for other implementations
- https://github.com/Equidamoid/pyconz/commits/master
- https://github.com/mozilla-iot/deconz-api
- https://github.com/adetante/deconz-sp
- https://github.com/frederic34/plugin-nodeBee

# How to contribute

If you are looking to make a contribution to this project we suggest that you follow the steps in these guides:
- https://github.com/firstcontributions/first-contributions/blob/master/README.md
- https://github.com/firstcontributions/first-contributions/blob/master/github-desktop-tutorial.md

Some developers might also be interested in receiving donations in the form of hardware such as Zigbee modules or devices, and even if such donations are most often donated with no strings attached it could in many cases help the developers motivation and indirect improve the development of this project.

## Related projects

### Zigpy
[Zvigpy](https://github.com/zigpy/zigpy)** is **[Zigbee protocol stack](https://en.wikipedia.org/wiki/Zigbee)** integration project to implement the **[Zigbee Home Automation](https://www.zigbee.org/)** standard as a Python 3 library. Zigbee Home Automation integration with zigpy allows you to connect one of many off-the-shelf Zigbee adapters using one of the available Zigbee radio library modules compatible with zigpy to control Zigbee based devices. There is currently support for controlling Zigbee device types such as binary sensors (e.g., motion and door sensors), sensors (e.g., temperature sensors), lightbulbs, switches, and fans. A working implementation of zigbe exist in **[Home Assistant](https://www.home-assistant.io)** (Python based open source home automation software) as part of its **[ZHA component](https://www.home-assistant.io/components/zha/)**

### ZHA Device Handlers
ZHA deviation handling in Home Assistant relies on on the third-party [ZHA Device Handlers](https://github.com/dmulcahey/zha-device-handlers) project. Zigbee devices that deviate from or do not fully conform to the standard specifications set by the [Zigbee Alliance](https://www.zigbee.org) may require the development of custom [ZHA Device Handlers](https://github.com/dmulcahey/zha-device-handlers) (ZHA custom quirks handler implementation) to for all their functions to work properly with the ZHA component in Home Assistant. These ZHA Device Handlers for Home Assistant can thus be used to parse custom messages to and from non-compliant Zigbee devices. The custom quirks implementations for zigpy implemented as ZHA Device Handlers for Home Assistant are a similar concept to that of [Hub-connected Device Handlers for the SmartThings Classics platform](https://docs.smartthings.com/en/latest/device-type-developers-guide/) as well as that of [Zigbee-Shepherd Converters as used by Zigbee2mqtt](https://www.zigbee2mqtt.io/how_tos/how_to_support_new_devices.html), meaning they are each virtual representations of a physical device that expose additional functionality that is not provided out-of-the-box by the existing integration between these platforms.

### ZHA Map
[zha-map](https://github.com/zha-ng/zha-map) project allow Home Assistant to build a ZHA network topology map.

### zha-network-visualization-card
[zha-network-visualization-card](https://github.com/dmulcahey/zha-network-visualization-card) is a custom Lovelace element for visualizing the ZHA Zigbee network in Home Assistant.

### ZHA Network Card
[zha-network-card](https://github.com/dmulcahey/zha-network-card) is a custom Lovelace card that displays ZHA network and device information in Home Assistant

### zigpy-deconz-parser
[zigpy-deconz-parser](https://github.com/zha-ng/zigpy-deconz-parser) project can parse HomeAssistant ZHA component debug log using `zigpy-deconz` library if you have Conbee or Raspbee hardware.
