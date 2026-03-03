##
## This file is part of the libsigrokdecode project.
##
## Copyright (C) 2025
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##

'''
This decoder stacks on top of the 'usb_request' PD and decodes USB standard
requests (Get Descriptor, Set Configuration, Set Interface, etc.) and parses
descriptor contents.

The decoder recognizes standard USB requests defined in the USB specification
and provides detailed parsing of descriptor data including:
- Device Descriptors
- Configuration Descriptors
- Interface Descriptors
- Endpoint Descriptors
- String Descriptors

Details:
https://en.wikipedia.org/wiki/USB
http://www.usb.org/developers/docs/
'''

from .pd import Decoder
