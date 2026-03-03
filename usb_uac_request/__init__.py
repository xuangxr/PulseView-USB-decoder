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
This decoder stacks on top of the 'usb_request' PD and decodes USB Audio Class (UAC)
requests and responses.

The decoder recognizes UAC-specific requests defined in the USB Audio Class specification
including:
- GET_CUR, SET_CUR (Current value)
- GET_MIN, GET_MAX, GET_RES (Range and resolution)
- GET_MEM, SET_MEM (Memory)
- GET_STAT (Status)

Details:
https://www.usb.org/document-library/audio-device-class-spec-basic-audio-devices-v10-and-adopters-agreement
http://www.usb.org/developers/docs/
'''

from .pd import Decoder
