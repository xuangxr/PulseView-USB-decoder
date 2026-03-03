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

import sigrokdecode as srd
import struct

'''
OUTPUT_PYTHON format:

Packet:
['REQUEST', <request_data>]

<request_data>:
 - 'type': Request type ('SETUP IN', 'SETUP OUT', etc.)
 - 'addr': Device address
 - 'ep': Endpoint number
 - 'setup_data': Setup packet bytes (8 bytes) or None
 - 'data': Data bytes or empty bytes
 - 'handshake': Handshake status ('ACK', 'NAK', 'STALL', etc.)
'''

# USB Request Type Masks
USB_REQ_TYPE_MASK = 0x60
USB_REQ_TYPE_STANDARD = 0x00
USB_REQ_TYPE_CLASS = 0x20
USB_REQ_TYPE_VENDOR = 0x40
USB_REQ_TYPE_RESERVED = 0x60

USB_REQ_DIR_MASK = 0x80
USB_REQ_DIR_HOST_TO_DEVICE = 0x00
USB_REQ_DIR_DEVICE_TO_HOST = 0x80

USB_REQ_RECIPIENT_MASK = 0x1F
USB_REQ_RECIPIENT_DEVICE = 0x00
USB_REQ_RECIPIENT_INTERFACE = 0x01
USB_REQ_RECIPIENT_ENDPOINT = 0x02
USB_REQ_RECIPIENT_OTHER = 0x03

# USB Audio Class Request Codes
# SET requests
UAC_REQ_CUR = 0x01  # SET_CUR
UAC_REQ_RANGE = 0x02  # SET_MIN, SET_MAX, SET_RES
UAC_REQ_MEM = 0x03  # SET_MEM
UAC_REQ_INTERRUPT = 0x04  # SET_STAT
# GET requests (SET request | 0x80)
UAC_REQ_GET_CUR = 0x81  # GET_CUR
UAC_REQ_GET_MIN = 0x82  # GET_MIN
UAC_REQ_GET_MAX = 0x83  # GET_MAX
UAC_REQ_GET_RES = 0x84  # GET_RES
UAC_REQ_GET_MEM = 0x83  # GET_MEM (same as GET_MAX, but different context)
UAC_REQ_GET_STAT = 0xFF  # GET_STAT

# USB Audio Class Control Selectors
# Feature Unit Control Selectors
UAC_FU_CONTROL_UNDEFINED = 0x00
UAC_FU_MUTE_CONTROL = 0x01
UAC_FU_VOLUME_CONTROL = 0x02
UAC_FU_BASS_CONTROL = 0x03
UAC_FU_MID_CONTROL = 0x04
UAC_FU_TREBLE_CONTROL = 0x05
UAC_FU_GRAPHIC_EQUALIZER_CONTROL = 0x06
UAC_FU_AUTOMATIC_GAIN_CONTROL = 0x07
UAC_FU_DELAY_CONTROL = 0x08
UAC_FU_BASS_BOOST_CONTROL = 0x09
UAC_FU_LOUDNESS_CONTROL = 0x0A

# Clock Source Control Selectors
UAC_CS_SAMPLING_FREQ_CONTROL = 0x01
UAC_CS_CLOCK_VALID_CONTROL = 0x01  # For Clock Source

# Sampling Rate Control Selectors
UAC_SR_CONTROL_UNDEFINED = 0x00
UAC_SR_SAMPLING_FREQ_CONTROL = 0x01
UAC_SR_MAX_SAMPLING_FREQ_CONTROL = 0x02
UAC_SR_MIN_SAMPLING_FREQ_CONTROL = 0x03

# Control Selector Names (most common mappings)
# Note: Control selector meaning depends on entity type
CONTROL_SELECTOR_NAMES = {
    0x00: 'Undefined',
    0x01: 'Control (0x01)',  # Could be Mute (Feature Unit) or Sampling Frequency (Clock Source/Sampling Rate)
    0x02: 'Control (0x02)',  # Could be Volume (Feature Unit) or Max Sampling Frequency (Sampling Rate)
    0x03: 'Control (0x03)',  # Could be Bass (Feature Unit) or Min Sampling Frequency (Sampling Rate)
    0x04: 'Mid',
    0x05: 'Treble',
    0x06: 'Graphic Equalizer',
    0x07: 'Automatic Gain',
    0x08: 'Delay',
    0x09: 'Bass Boost',
    0x0A: 'Loudness',
}

# Feature Unit specific names
FEATURE_UNIT_SELECTOR_NAMES = {
    0x00: 'Undefined',
    0x01: 'Mute',
    0x02: 'Volume',
    0x03: 'Bass',
    0x04: 'Mid',
    0x05: 'Treble',
    0x06: 'Graphic Equalizer',
    0x07: 'Automatic Gain',
    0x08: 'Delay',
    0x09: 'Bass Boost',
    0x0A: 'Loudness',
}

# Clock Source / Sampling Rate specific names
SAMPLING_RATE_SELECTOR_NAMES = {
    0x00: 'Undefined',
    0x01: 'Sampling Frequency',
    0x02: 'Max Sampling Frequency',
    0x03: 'Min Sampling Frequency',
}

# USB Audio Class Entity Types
UAC_ENTITY_UNDEFINED = 0x00
UAC_ENTITY_INPUT_TERMINAL = 0x01
UAC_ENTITY_OUTPUT_TERMINAL = 0x02
UAC_ENTITY_MIXER_UNIT = 0x03
UAC_ENTITY_SELECTOR_UNIT = 0x04
UAC_ENTITY_FEATURE_UNIT = 0x05
UAC_ENTITY_PROCESSING_UNIT = 0x06
UAC_ENTITY_EXTENSION_UNIT = 0x07
UAC_ENTITY_CLOCK_SOURCE = 0x0A
UAC_ENTITY_CLOCK_SELECTOR = 0x0B
UAC_ENTITY_CLOCK_MULTIPLIER = 0x0C
UAC_ENTITY_SAMPLE_RATE_CONVERTER = 0x0D

ENTITY_TYPE_NAMES = {
    UAC_ENTITY_UNDEFINED: 'Undefined',
    UAC_ENTITY_INPUT_TERMINAL: 'Input Terminal',
    UAC_ENTITY_OUTPUT_TERMINAL: 'Output Terminal',
    UAC_ENTITY_MIXER_UNIT: 'Mixer Unit',
    UAC_ENTITY_SELECTOR_UNIT: 'Selector Unit',
    UAC_ENTITY_FEATURE_UNIT: 'Feature Unit',
    UAC_ENTITY_PROCESSING_UNIT: 'Processing Unit',
    UAC_ENTITY_EXTENSION_UNIT: 'Extension Unit',
    UAC_ENTITY_CLOCK_SOURCE: 'Clock Source',
    UAC_ENTITY_CLOCK_SELECTOR: 'Clock Selector',
    UAC_ENTITY_CLOCK_MULTIPLIER: 'Clock Multiplier',
    UAC_ENTITY_SAMPLE_RATE_CONVERTER: 'Sample Rate Converter',
}

# USB Audio Terminal Types
TERMINAL_TYPE_USB_STREAMING = 0x0101
TERMINAL_TYPE_MICROPHONE = 0x0201
TERMINAL_TYPE_DESKTOP_MICROPHONE = 0x0202
TERMINAL_TYPE_PERSONAL_MICROPHONE = 0x0203
TERMINAL_TYPE_OMNI_DIRECTIONAL_MICROPHONE = 0x0204
TERMINAL_TYPE_MICROPHONE_ARRAY = 0x0205
TERMINAL_TYPE_PROCESSING_MICROPHONE_ARRAY = 0x0206
TERMINAL_TYPE_SPEAKER = 0x0301
TERMINAL_TYPE_HEADPHONES = 0x0302
TERMINAL_TYPE_HEAD_MOUNTED_DISPLAY_AUDIO = 0x0303
TERMINAL_TYPE_DESKTOP_SPEAKER = 0x0304
TERMINAL_TYPE_ROOM_SPEAKER = 0x0305
TERMINAL_TYPE_COMMUNICATION_SPEAKER = 0x0306
TERMINAL_TYPE_LOW_FREQUENCY_EFFECTS_SPEAKER = 0x0307

TERMINAL_TYPE_NAMES = {
    0x0101: 'USB Streaming',
    0x0201: 'Microphone',
    0x0202: 'Desktop Microphone',
    0x0203: 'Personal Microphone',
    0x0204: 'Omni-directional Microphone',
    0x0205: 'Microphone Array',
    0x0206: 'Processing Microphone Array',
    0x0301: 'Speaker',
    0x0302: 'Headphones',
    0x0303: 'Head Mounted Display Audio',
    0x0304: 'Desktop Speaker',
    0x0305: 'Room Speaker',
    0x0306: 'Communication Speaker',
    0x0307: 'Low Frequency Effects Speaker',
}

# Request Names
REQUEST_NAMES = {
    UAC_REQ_CUR: 'SET_CUR',
    UAC_REQ_RANGE: 'SET_RANGE',
    UAC_REQ_MEM: 'SET_MEM',
    UAC_REQ_INTERRUPT: 'SET_STAT',
    UAC_REQ_GET_CUR: 'GET_CUR',
    UAC_REQ_GET_MIN: 'GET_MIN',
    UAC_REQ_GET_MAX: 'GET_MAX',
    UAC_REQ_GET_RES: 'GET_RES',
    UAC_REQ_GET_MEM: 'GET_MEM',
    UAC_REQ_GET_STAT: 'GET_STAT',
}

class Decoder(srd.Decoder):
    api_version = 3
    id = 'usb_uac_request'
    name = 'USB UAC Request'
    longname = 'USB Audio Class Request Decoder'
    desc = 'Decodes USB Audio Class (UAC) requests (GET_CUR, SET_CUR, GET_MIN, GET_MAX, etc.)'
    license = 'gplv2+'
    inputs = ['usb_standard_request', 'usb_request']
    outputs = ['usb_uac_request']
    tags = ['PC', 'Audio']
    annotations = (
        ('request-name', 'Request name'),
        ('request-details', 'Request details'),
        ('control-selector', 'Control selector'),
        ('value', 'Value'),
        ('error', 'Error'),
    )
    annotation_rows = (
        ('requests', 'UAC Requests', (0, 1)),
        ('controls', 'Control Selectors', (2, 3)),
        ('errors', 'Errors', (4,)),
    )

    def __init__(self):
        self.reset()

    def reset(self):
        self.pending_request = None
        # Store UAC interface and entity information from configuration descriptor
        # Format: {interface_id: {'class': int, 'subclass': int, 'protocol': int, 'entities': [...]}}
        self.uac_interfaces = {}
        # Format: {entity_id: {'type': int, 'name': str, 'interface_id': int}}
        self.uac_entities = {}
        # Store configuration descriptor data for parsing
        self.config_descriptor_data = None

    def start(self):
        self.out_ann = self.register(srd.OUTPUT_ANN)

    def puta(self, ss, es, ann, text):
        self.put(ss, es, self.out_ann, [ann, text])

    def parse_setup_packet(self, setup_data):
        """Parse USB setup packet (8 bytes)."""
        if len(setup_data) < 8:
            return None
        
        bmRequestType = setup_data[0]
        bRequest = setup_data[1]
        wValue = struct.unpack('<H', setup_data[2:4])[0]
        wIndex = struct.unpack('<H', setup_data[4:6])[0]
        wLength = struct.unpack('<H', setup_data[6:8])[0]
        
        return {
            'bmRequestType': bmRequestType,
            'bRequest': bRequest,
            'wValue': wValue,
            'wIndex': wIndex,
            'wLength': wLength,
        }

    def is_class_request(self, bmRequestType):
        """Check if this is a class-specific request."""
        return (bmRequestType & USB_REQ_TYPE_MASK) == USB_REQ_TYPE_CLASS

    def get_request_name(self, bRequest):
        """Get human-readable request name."""
        return REQUEST_NAMES.get(bRequest, 'UNKNOWN (0x%02X)' % bRequest)

    def get_control_selector_name(self, selector, entity_type=None):
        """Get human-readable control selector name.
        
        Args:
            selector: Control selector value
            entity_type: Optional entity type hint (e.g., 'feature_unit', 'clock_source', 'sampling_rate')
        """
        # Try entity-specific names first if entity type is known
        if entity_type == 'feature_unit':
            return FEATURE_UNIT_SELECTOR_NAMES.get(selector, 'Unknown (0x%02X)' % selector)
        elif entity_type in ('clock_source', 'sampling_rate'):
            return SAMPLING_RATE_SELECTOR_NAMES.get(selector, 'Unknown (0x%02X)' % selector)
        
        # Default: use generic names
        return CONTROL_SELECTOR_NAMES.get(selector, 'Unknown (0x%02X)' % selector)

    def parse_cur_value(self, data, ss, es, is_get=True):
        """Parse CUR (Current) value."""
        if len(data) == 0:
            return
        
        # CUR values are typically 1-2 bytes depending on control
        if len(data) >= 2:
            value = struct.unpack('<H', data[0:2])[0]
            fields = []
            fields.append('Current Value: %d' % value)
            if len(data) > 2:
                hex_str = ' '.join(['%02X' % b for b in data[2:]])
                fields.append('Additional Data: %s' % hex_str)
            multi_line = '\n'.join(fields)
            short_summary = 'Value: %d' % value
            self.puta(ss, es, 3, [multi_line, short_summary])
        elif len(data) == 1:
            value = data[0]
            self.puta(ss, es, 3, ['Current Value: %d' % value])

    def parse_range_value(self, data, ss, es, range_type):
        """Parse RANGE (MIN/MAX/RES) value."""
        if len(data) < 2:
            return
        
        value = struct.unpack('<H', data[0:2])[0]
        range_names = {
            0x81: 'MIN',
            0x82: 'MAX',
            0x83: 'RES',
        }
        range_name = range_names.get(range_type, 'RANGE')
        self.puta(ss, es, 3, ['%s Value: %d' % (range_name, value)])

    def decode_uac_request(self, setup, data, ss, es):
        """Decode a USB Audio Class request."""
        bmRequestType = setup['bmRequestType']
        bRequest = setup['bRequest']
        wValue = setup['wValue']
        wIndex = setup['wIndex']
        wLength = setup['wLength']
        
        # Get request direction
        direction = 'Device-to-Host' if (bmRequestType & USB_REQ_DIR_MASK) else 'Host-to-Device'
        
        # Get recipient
        recipient = bmRequestType & USB_REQ_RECIPIENT_MASK
        recipient_names = {
            USB_REQ_RECIPIENT_DEVICE: 'Device',
            USB_REQ_RECIPIENT_INTERFACE: 'Interface',
            USB_REQ_RECIPIENT_ENDPOINT: 'Endpoint',
            USB_REQ_RECIPIENT_OTHER: 'Other',
        }
        recipient_name = recipient_names.get(recipient, 'Unknown')
        
        # Get request name
        req_name = self.get_request_name(bRequest)
        
        # Parse wValue: high byte = control selector, low byte = channel number
        control_selector = (wValue >> 8) & 0xFF
        channel = wValue & 0xFF
        
        # Parse wIndex: format depends on recipient
        # For Interface recipient: low byte = interface number, high byte may be used for other purposes
        # For Entity recipient: low byte = entity ID, high byte = unit ID
        if recipient == USB_REQ_RECIPIENT_INTERFACE:
            interface_id = wIndex & 0xFF
            entity_id = (wIndex >> 8) & 0xFF
        else:
            entity_id = wIndex & 0xFF
            interface_id = (wIndex >> 8) & 0xFF
        
        # Try to determine entity type from context
        # Use stored entity information if available
        entity_type = None
        entity_info = None
        
        if entity_id > 0 and entity_id in self.uac_entities:
            entity_info = self.uac_entities[entity_id]
            entity_type_code = entity_info.get('type')
            if entity_type_code == UAC_ENTITY_FEATURE_UNIT:
                entity_type = 'feature_unit'
            elif entity_type_code == UAC_ENTITY_CLOCK_SOURCE:
                entity_type = 'clock_source'
            elif entity_type_code == UAC_ENTITY_SAMPLE_RATE_CONVERTER:
                entity_type = 'sampling_rate'
        
        # Fallback: determine entity type from context
        if entity_type is None:
            if recipient == USB_REQ_RECIPIENT_INTERFACE:
                # Interface recipient often indicates Sampling Rate Control
                if control_selector in (0x01, 0x02, 0x03):
                    entity_type = 'sampling_rate'
            elif recipient == USB_REQ_RECIPIENT_OTHER:
                # Entity recipient - could be Feature Unit or Clock Source
                # Default to Feature Unit for common selectors
                if control_selector <= 0x0A:
                    entity_type = 'feature_unit'
        
        # Build request annotation
        # Handle GET requests (0x81-0x84) and SET requests (0x01-0x04)
        if bRequest == UAC_REQ_CUR or bRequest == UAC_REQ_GET_CUR:
            req_display = 'GET_CUR' if bRequest == UAC_REQ_GET_CUR else 'SET_CUR'
            control_name = self.get_control_selector_name(control_selector, entity_type)
            fields = []
            fields.append('%s' % req_display)
            fields.append('Control: %s' % control_name)
            if channel > 0:
                fields.append('Channel: %d' % channel)
            if entity_id > 0:
                entity_name = self.uac_entities.get(entity_id, {}).get('name', 'Entity %d' % entity_id)
                fields.append('Entity: %s (ID: %d)' % (entity_name, entity_id))
            if interface_id > 0:
                fields.append('Interface ID: %d' % interface_id)
            multi_line = '\n'.join(fields)
            short_summary = '%s %s' % (req_display, control_name)
            self.puta(ss, es, 0, [multi_line, short_summary])
            
            # Parse value if present
            if len(data) > 0:
                self.parse_cur_value(data, ss, es, bRequest == UAC_REQ_GET_CUR)
        elif bRequest == UAC_REQ_GET_MIN:
            req_display = 'GET_MIN'
            control_name = self.get_control_selector_name(control_selector, entity_type)
            fields = []
            fields.append('%s' % req_display)
            fields.append('Control: %s' % control_name)
            if channel > 0:
                fields.append('Channel: %d' % channel)
            if entity_id > 0:
                fields.append('Entity ID: %d' % entity_id)
            if interface_id > 0:
                fields.append('Interface ID: %d' % interface_id)
            multi_line = '\n'.join(fields)
            short_summary = '%s %s' % (req_display, control_name)
            self.puta(ss, es, 0, [multi_line, short_summary])
            
            # Parse MIN value
            if len(data) >= 2:
                value = struct.unpack('<H', data[0:2])[0]
                self.puta(ss, es, 3, ['MIN Value: %d' % value])
        elif bRequest == UAC_REQ_GET_MAX:
            req_display = 'GET_MAX'
            control_name = self.get_control_selector_name(control_selector, entity_type)
            fields = []
            fields.append('%s' % req_display)
            fields.append('Control: %s' % control_name)
            if channel > 0:
                fields.append('Channel: %d' % channel)
            if entity_id > 0:
                fields.append('Entity ID: %d' % entity_id)
            if interface_id > 0:
                fields.append('Interface ID: %d' % interface_id)
            multi_line = '\n'.join(fields)
            short_summary = '%s %s' % (req_display, control_name)
            self.puta(ss, es, 0, [multi_line, short_summary])
            
            # Parse MAX value
            if len(data) >= 2:
                value = struct.unpack('<H', data[0:2])[0]
                self.puta(ss, es, 3, ['MAX Value: %d' % value])
        elif bRequest == UAC_REQ_GET_RES:
            req_display = 'GET_RES'
            control_name = self.get_control_selector_name(control_selector, entity_type)
            fields = []
            fields.append('%s' % req_display)
            fields.append('Control: %s' % control_name)
            if channel > 0:
                fields.append('Channel: %d' % channel)
            if entity_id > 0:
                fields.append('Entity ID: %d' % entity_id)
            if interface_id > 0:
                fields.append('Interface ID: %d' % interface_id)
            multi_line = '\n'.join(fields)
            short_summary = '%s %s' % (req_display, control_name)
            self.puta(ss, es, 0, [multi_line, short_summary])
            
            # Parse RES value
            if len(data) >= 2:
                value = struct.unpack('<H', data[0:2])[0]
                self.puta(ss, es, 3, ['RES Value: %d' % value])
        elif bRequest == UAC_REQ_RANGE:
            if direction == 'Device-to-Host':
                req_display = 'GET_RANGE'
            else:
                req_display = 'SET_RANGE'
            control_name = self.get_control_selector_name(control_selector, entity_type)
            fields = []
            fields.append('%s' % req_display)
            fields.append('Control: %s' % control_name)
            if channel > 0:
                fields.append('Channel: %d' % channel)
            if entity_id > 0:
                fields.append('Entity ID: %d' % entity_id)
            multi_line = '\n'.join(fields)
            short_summary = '%s %s' % (req_display, control_name)
            self.puta(ss, es, 0, [multi_line, short_summary])
            
            # Parse range values (MIN/MAX/RES)
            if len(data) > 0:
                # Range requests return multiple values
                offset = 0
                while offset + 2 <= len(data):
                    value = struct.unpack('<H', data[offset:offset+2])[0]
                    if offset == 0:
                        self.puta(ss, es, 3, ['MIN Value: %d' % value])
                    elif offset == 2:
                        self.puta(ss, es, 3, ['MAX Value: %d' % value])
                    elif offset == 4:
                        self.puta(ss, es, 3, ['RES Value: %d' % value])
                    offset += 2
        elif bRequest == UAC_REQ_MEM or bRequest == UAC_REQ_GET_MEM:
            req_display = 'GET_MEM' if bRequest == UAC_REQ_GET_MEM else 'SET_MEM'
            fields = []
            fields.append('%s' % req_display)
            if entity_id > 0:
                fields.append('Entity ID: %d' % entity_id)
            multi_line = '\n'.join(fields)
            short_summary = req_display
            self.puta(ss, es, 0, [multi_line, short_summary])
        elif bRequest == UAC_REQ_INTERRUPT or bRequest == UAC_REQ_GET_STAT:
            req_display = 'GET_STAT' if bRequest == UAC_REQ_GET_STAT else 'SET_STAT'
            fields = []
            fields.append('%s' % req_display)
            if entity_id > 0:
                fields.append('Entity ID: %d' % entity_id)
            multi_line = '\n'.join(fields)
            short_summary = req_display
            self.puta(ss, es, 0, [multi_line, short_summary])
        else:
            self.puta(ss, es, 0, ['UAC Request %s (0x%02X)' % (req_name, bRequest)])

    def parse_config_descriptor(self, data, ss, es):
        """Parse configuration descriptor to extract UAC interface and entity information."""
        # Convert to bytearray if needed
        if isinstance(data, bytes):
            data = bytearray(data)
        elif isinstance(data, list):
            data = bytearray(data)
        
        if len(data) < 9:
            return
        
        # Skip configuration descriptor header (9 bytes)
        offset = 9
        
        current_interface_id = None
        current_interface_class = None
        current_alt_setting = None
        detailed_fields = []  # Store detailed descriptor information for display
        
        while offset < len(data):
            if offset + 2 > len(data):
                break
            
            desc_len = data[offset]
            desc_type = data[offset + 1]
            
            if desc_len == 0 or desc_len < 2:
                break
            
            if offset + desc_len > len(data):
                desc_len = len(data) - offset
            
            desc_data = data[offset:offset + desc_len]
            
            # Parse Interface Descriptor - only for Audio Class interfaces
            if desc_type == 0x04:  # USB_DT_INTERFACE
                if len(desc_data) >= 9:
                    interface_id = desc_data[2]
                    alt_setting = desc_data[3]
                    num_eps = desc_data[4]
                    interface_class = desc_data[5]
                    interface_subclass = desc_data[6]
                    interface_protocol = desc_data[7]
                    iInterface = desc_data[8]
                    
                    # Only process Audio Class interfaces (0x01)
                    if interface_class == 0x01:  # Audio Class
                        current_interface_id = interface_id
                        current_alt_setting = alt_setting
                        current_interface_class = interface_class
                        
                        if interface_id not in self.uac_interfaces:
                            self.uac_interfaces[interface_id] = {
                                'class': interface_class,
                                'subclass': interface_subclass,
                                'protocol': interface_protocol,
                                'entities': [],
                                'alt_settings': {}
                            }
                        
                        # Store alternate setting info
                        if alt_setting not in self.uac_interfaces[interface_id]['alt_settings']:
                            self.uac_interfaces[interface_id]['alt_settings'][alt_setting] = {
                                'num_endpoints': num_eps,
                                'iInterface': iInterface
                            }
                        
                        # Add detailed interface descriptor info
                        subclass_names = {
                            0x01: 'Audio Control',
                            0x02: 'Audio Streaming',
                            0x03: 'MIDI Streaming',
                        }
                        subclass_name = subclass_names.get(interface_subclass, 'Unknown')
                        detailed_fields.append('IF%d.%d: %s | EPs:%d' % (interface_id, alt_setting, subclass_name, num_eps))
                    else:
                        # Not an Audio Class interface, reset current interface tracking
                        current_interface_id = None
                        current_interface_class = None
            
            # Parse Class-Specific Interface Descriptor (CS_INTERFACE) - only for Audio Class
            elif desc_type == 0x24 and current_interface_class == 0x01:  # CS_INTERFACE, Audio Class only
                if len(desc_data) >= 3:
                    descriptor_subtype = desc_data[2]
                    
                    subtype_names = {
                        0x01: 'Header Descriptor',
                        0x02: 'Input terminal descriptor',
                        0x03: 'Output terminal descriptor',
                        0x06: 'Feature unit descriptor',
                        0x0A: 'Clock Source descriptor',
                    }
                    subtype_name = subtype_names.get(descriptor_subtype, 'Unknown')
                    
                    # Header Descriptor (subtype 0x01)
                    if descriptor_subtype == 0x01 and len(desc_data) >= 7:
                        bcdADC = struct.unpack('<H', desc_data[3:5])[0]
                        wTotalLength = struct.unpack('<H', desc_data[5:7])[0]
                        bInCollection = desc_data[7] if len(desc_data) > 7 else 0
                        if len(desc_data) > 8:
                            interface_nums = []
                            for i in range(8, min(len(desc_data), 8 + bInCollection)):
                                baInterfaceNr = desc_data[i]
                                interface_nums.append(str(baInterfaceNr))
                            if interface_nums:
                                detailed_fields.append('\t%s: Ver %d.%02d | IFs: %s' % (subtype_name, (bcdADC >> 8) & 0xFF, bcdADC & 0xFF, ', '.join(interface_nums)))
                            else:
                                detailed_fields.append('\t%s: Ver %d.%02d | %d IFs' % (subtype_name, (bcdADC >> 8) & 0xFF, bcdADC & 0xFF, bInCollection))
                        else:
                            detailed_fields.append('\t%s: Ver %d.%02d | %d IFs' % (subtype_name, (bcdADC >> 8) & 0xFF, bcdADC & 0xFF, bInCollection))
                    
                    # Input Terminal Descriptor (subtype 0x02)
                    elif descriptor_subtype == 0x02 and len(desc_data) >= 12:
                        entity_id = desc_data[3]
                        terminal_type = struct.unpack('<H', desc_data[4:6])[0]
                        assoc_terminal = desc_data[6]
                        num_channels = desc_data[7]
                        channel_config = struct.unpack('<H', desc_data[8:10])[0] if len(desc_data) >= 10 else 0
                        channel_names = desc_data[10] if len(desc_data) > 10 else 0
                        iTerminal = desc_data[11] if len(desc_data) > 11 else 0
                        
                        terminal_type_name = TERMINAL_TYPE_NAMES.get(terminal_type, '0x%04X' % terminal_type)
                        channel_info = '%d ch' % num_channels
                        if channel_config != 0:
                            channel_bits = []
                            if channel_config & 0x0001:
                                channel_bits.append('L')
                            if channel_config & 0x0002:
                                channel_bits.append('R')
                            if channel_config & 0x0004:
                                channel_bits.append('C')
                            if channel_config & 0x0008:
                                channel_bits.append('LFE')
                            if channel_bits:
                                channel_info += ' (%s)' % '/'.join(channel_bits)
                        detailed_fields.append('\t%s ID:%d | Type:%s | Assoc:%d | %s' % 
                                            (subtype_name, entity_id, terminal_type_name, assoc_terminal, channel_info))
                        
                        self.uac_entities[entity_id] = {
                            'type': UAC_ENTITY_INPUT_TERMINAL,
                            'name': ENTITY_TYPE_NAMES.get(UAC_ENTITY_INPUT_TERMINAL, 'Input Terminal'),
                            'interface_id': current_interface_id,
                            'terminal_type': terminal_type
                        }
                        if current_interface_id is not None:
                            self.uac_interfaces[current_interface_id]['entities'].append(entity_id)
                    
                    # Output Terminal Descriptor (subtype 0x03)
                    elif descriptor_subtype == 0x03 and len(desc_data) >= 9:
                        entity_id = desc_data[3]
                        terminal_type = struct.unpack('<H', desc_data[4:6])[0]
                        assoc_terminal = desc_data[6]
                        source_id = desc_data[7]
                        iTerminal = desc_data[8] if len(desc_data) > 8 else 0
                        
                        terminal_type_name = TERMINAL_TYPE_NAMES.get(terminal_type, '0x%04X' % terminal_type)
                        detailed_fields.append('\t%s ID:%d | Type:%s | Assoc:%d | Source:%d' % 
                                            (subtype_name, entity_id, terminal_type_name, assoc_terminal, source_id))
                        
                        self.uac_entities[entity_id] = {
                            'type': UAC_ENTITY_OUTPUT_TERMINAL,
                            'name': ENTITY_TYPE_NAMES.get(UAC_ENTITY_OUTPUT_TERMINAL, 'Output Terminal'),
                            'interface_id': current_interface_id,
                            'terminal_type': terminal_type
                        }
                        if current_interface_id is not None:
                            self.uac_interfaces[current_interface_id]['entities'].append(entity_id)
                    
                    # Feature Unit Descriptor (subtype 0x06)
                    elif descriptor_subtype == 0x06 and len(desc_data) >= 7:
                        entity_id = desc_data[3]
                        source_id = desc_data[4]
                        control_size = desc_data[5]
                        controls = struct.unpack('<H', desc_data[6:8])[0] if len(desc_data) >= 8 else 0
                        
                        # Decode control bits for master channel (bit 0)
                        control_features = []
                        if controls & 0x0001:
                            control_features.append('Mute')
                        if controls & 0x0002:
                            control_features.append('Vol')
                        if controls & 0x0004:
                            control_features.append('Bass')
                        if controls & 0x0008:
                            control_features.append('Mid')
                        if controls & 0x0010:
                            control_features.append('Treble')
                        if controls & 0x0020:
                            control_features.append('EQ')
                        if controls & 0x0040:
                            control_features.append('AGC')
                        if controls & 0x0080:
                            control_features.append('Delay')
                        
                        control_info = '0x%04X' % controls
                        if control_features:
                            control_info += ' (%s)' % '/'.join(control_features)
                        
                        detailed_fields.append('\t%s ID:%d | Source:%d | %s' % 
                                            (subtype_name, entity_id, source_id, control_info))
                        
                        self.uac_entities[entity_id] = {
                            'type': UAC_ENTITY_FEATURE_UNIT,
                            'name': ENTITY_TYPE_NAMES.get(UAC_ENTITY_FEATURE_UNIT, 'Feature Unit'),
                            'interface_id': current_interface_id
                        }
                        if current_interface_id is not None:
                            self.uac_interfaces[current_interface_id]['entities'].append(entity_id)
                    
                    # Clock Source Descriptor (subtype 0x0A)
                    elif descriptor_subtype == 0x0A and len(desc_data) >= 8:
                        entity_id = desc_data[3]
                        clock_attributes = desc_data[4]
                        clock_id = desc_data[5]
                        detailed_fields.append('\t%s ID:%d | Attr:0x%02X' % (subtype_name, entity_id, clock_attributes))
                        
                        self.uac_entities[entity_id] = {
                            'type': UAC_ENTITY_CLOCK_SOURCE,
                            'name': ENTITY_TYPE_NAMES.get(UAC_ENTITY_CLOCK_SOURCE, 'Clock Source'),
                            'interface_id': current_interface_id
                        }
                        if current_interface_id is not None:
                            self.uac_interfaces[current_interface_id]['entities'].append(entity_id)
            
            # Parse Endpoint Descriptor - only for Audio Class interfaces
            elif desc_type == 0x05 and current_interface_class == 0x01:  # USB_DT_ENDPOINT, Audio Class only
                if len(desc_data) >= 7:
                    ep_addr = desc_data[2]
                    ep_num = ep_addr & 0x0F
                    ep_dir = 'IN' if (ep_addr & 0x80) else 'OUT'
                    bm_attrs = desc_data[3]
                    transfer_type = bm_attrs & 0x03
                    sync_type = (bm_attrs >> 2) & 0x03
                    usage_type = (bm_attrs >> 4) & 0x03
                    wMaxPacketSize = struct.unpack('<H', desc_data[4:6])[0]
                    bInterval = desc_data[6] if len(desc_data) > 6 else 0
                    
                    transfer_names = ['Ctrl', 'Iso', 'Bulk', 'Int']
                    sync_names = ['None', 'Async', 'Adapt', 'Sync']
                    
                    if len(desc_data) >= 9:
                        bRefresh = desc_data[7] if len(desc_data) > 7 else 0
                        bSynchAddress = desc_data[8] if len(desc_data) > 8 else 0
                        detailed_fields.append('\tEP%d%s: %s/%s | MaxPkt:%d | Int:%d' % 
                                            (ep_num, ep_dir, transfer_names[transfer_type], sync_names[sync_type], wMaxPacketSize, bInterval))
                    else:
                        detailed_fields.append('\tEP%d%s: %s/%s | MaxPkt:%d | Int:%d' % 
                                            (ep_num, ep_dir, transfer_names[transfer_type], sync_names[sync_type], wMaxPacketSize, bInterval))
            
            # Parse Class-Specific Endpoint Descriptor (CS_ENDPOINT) - only for Audio Class
            elif desc_type == 0x25 and current_interface_class == 0x01:  # CS_ENDPOINT, Audio Class only
                if len(desc_data) >= 4:
                    descriptor_subtype = desc_data[2]
                    attributes = desc_data[3] if len(desc_data) > 3 else 0
                    attr_parts = []
                    if attributes & 0x01:
                        attr_parts.append('FreqCtrl')
                    if attributes & 0x02:
                        attr_parts.append('PitchCtrl')
                    attr_str = ', '.join(attr_parts) if attr_parts else 'None'
                    detailed_fields.append('\tCS Endpoint: Attr:0x%02X (%s)' % (attributes, attr_str))
            
            offset += desc_len
        
        # Display parsed UAC interface and entity information
        if detailed_fields:
            fields = []
            fields.append('UAC Configuration Descriptor Parsed')
            fields.extend(detailed_fields)
            
            multi_line = '\n'.join(fields)
            short_summary = 'UAC Config: %d interface(s), %d entity(ies)' % \
                          (len(self.uac_interfaces), len(self.uac_entities))
            self.puta(ss, es, 1, [multi_line, short_summary])

    def decode(self, ss, es, data):
        ptype, pdata = data
        
        # Handle data from usb_standard_request decoder
        # It outputs CLASS_REQUEST for class-specific requests
        # It also outputs REQUEST for standard requests (including GET_DESCRIPTOR CONFIGURATION)
        if ptype == 'CLASS_REQUEST':
            request = pdata
            request_type = request.get('type', 'SETUP IN')
            setup_data = request.get('setup_data')
            data_bytes = request.get('data', b'')
        elif ptype == 'REQUEST':
            # Handle GET_DESCRIPTOR CONFIGURATION requests to parse UAC interfaces
            request = pdata
            request_type = request.get('type', 'SETUP IN')
            setup_data = request.get('setup_data')
            data_bytes = request.get('data', b'')
            
            if setup_data and len(setup_data) >= 8:
                bRequest = setup_data[1]
                wValue = struct.unpack('<H', setup_data[2:4])[0]
                desc_type = (wValue >> 8) & 0xFF
                
                # Check if this is a GET_DESCRIPTOR CONFIGURATION request
                if bRequest == 0x06 and desc_type == 0x02 and len(data_bytes) > 0:
                    # Convert data_bytes to bytearray if needed
                    if isinstance(data_bytes, bytes):
                        config_data = bytearray(data_bytes)
                    elif isinstance(data_bytes, list):
                        config_data = bytearray(data_bytes)
                    else:
                        config_data = bytearray(data_bytes)
                    
                    # Parse configuration descriptor to extract UAC information
                    self.parse_config_descriptor(config_data, ss, es)
                    return  # Don't process as UAC request
        else:
            return  # Only process class requests or configuration descriptors
        
        # Only process SETUP requests (control transfers)
        if request_type not in ('SETUP IN', 'SETUP OUT'):
            return
        
        if setup_data is None:
            return
        
        # Convert bytes to bytearray if needed
        if isinstance(setup_data, bytes):
            setup_data = bytearray(setup_data)
        elif isinstance(setup_data, list):
            setup_data = bytearray(setup_data)
        
        if len(setup_data) < 8:
            return
        
        if isinstance(data_bytes, bytes):
            data_bytes = bytearray(data_bytes)
        elif isinstance(data_bytes, list):
            data_bytes = bytearray(data_bytes)
        elif data_bytes is None:
            data_bytes = bytearray()
        
        # Parse setup packet
        setup = self.parse_setup_packet(setup_data)
        if setup is None:
            self.puta(ss, es, 4, ['Invalid setup packet'])
            return
        
        # Check if this is a class-specific request
        if not self.is_class_request(setup['bmRequestType']):
            return  # Not a class request, skip
        
        # Additional check: verify this looks like a UAC request
        # UAC requests have bRequest in range 0x01-0x04 (SET) or 0x81-0x84 (GET)
        bRequest = setup['bRequest']
        # Check if recipient is Interface (common for UAC)
        recipient = setup['bmRequestType'] & USB_REQ_RECIPIENT_MASK
        if bRequest not in (UAC_REQ_CUR, UAC_REQ_RANGE, UAC_REQ_MEM, UAC_REQ_INTERRUPT,
                           UAC_REQ_GET_CUR, UAC_REQ_GET_MIN, UAC_REQ_GET_MAX, UAC_REQ_GET_RES,
                           UAC_REQ_GET_MEM, UAC_REQ_GET_STAT):
            # Might be another class request, but if it's to Interface and bRequest is in UAC range, try to decode anyway
            if recipient == USB_REQ_RECIPIENT_INTERFACE and (0x01 <= bRequest <= 0x04 or 0x81 <= bRequest <= 0x84):
                # Likely a UAC request, proceed
                pass
            else:
                # Probably not a UAC request, skip
                return
        
        # Decode the UAC request
        self.decode_uac_request(setup, data_bytes, ss, es)
