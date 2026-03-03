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
 - 'type': Request type ('SETUP IN', 'SETUP OUT', 'BULK IN', etc.)
 - 'addr': Device address
 - 'ep': Endpoint number
 - 'setup_data': Setup packet bytes (8 bytes) or None
 - 'data': Data bytes or empty bytes
 - 'handshake': Handshake status ('ACK', 'NAK', 'STALL', etc.)
'''

# USB Standard Request Codes
USB_REQ_GET_STATUS = 0x00
USB_REQ_CLEAR_FEATURE = 0x01
USB_REQ_SET_FEATURE = 0x03
USB_REQ_SET_ADDRESS = 0x05
USB_REQ_GET_DESCRIPTOR = 0x06
USB_REQ_SET_DESCRIPTOR = 0x07
USB_REQ_GET_CONFIGURATION = 0x08
USB_REQ_SET_CONFIGURATION = 0x09
USB_REQ_GET_INTERFACE = 0x0A
USB_REQ_SET_INTERFACE = 0x0B
USB_REQ_SYNCH_FRAME = 0x0C

# USB Descriptor Types
USB_DT_DEVICE = 0x01
USB_DT_CONFIG = 0x02
USB_DT_STRING = 0x03
USB_DT_INTERFACE = 0x04
USB_DT_ENDPOINT = 0x05
USB_DT_DEVICE_QUALIFIER = 0x06
USB_DT_OTHER_SPEED_CONFIG = 0x07
USB_DT_INTERFACE_POWER = 0x08

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

# Standard Request Names
REQUEST_NAMES = {
    USB_REQ_GET_STATUS: 'GET_STATUS',
    USB_REQ_CLEAR_FEATURE: 'CLEAR_FEATURE',
    USB_REQ_SET_FEATURE: 'SET_FEATURE',
    USB_REQ_SET_ADDRESS: 'SET_ADDRESS',
    USB_REQ_GET_DESCRIPTOR: 'GET_DESCRIPTOR',
    USB_REQ_SET_DESCRIPTOR: 'SET_DESCRIPTOR',
    USB_REQ_GET_CONFIGURATION: 'GET_CONFIGURATION',
    USB_REQ_SET_CONFIGURATION: 'SET_CONFIGURATION',
    USB_REQ_GET_INTERFACE: 'GET_INTERFACE',
    USB_REQ_SET_INTERFACE: 'SET_INTERFACE',
    USB_REQ_SYNCH_FRAME: 'SYNCH_FRAME',
}

# Descriptor Type Names
DESCRIPTOR_NAMES = {
    USB_DT_DEVICE: 'Device',
    USB_DT_CONFIG: 'Configuration',
    USB_DT_STRING: 'String',
    USB_DT_INTERFACE: 'Interface',
    USB_DT_ENDPOINT: 'Endpoint',
    USB_DT_DEVICE_QUALIFIER: 'Device Qualifier',
    USB_DT_OTHER_SPEED_CONFIG: 'Other Speed Configuration',
    USB_DT_INTERFACE_POWER: 'Interface Power',
}

class Decoder(srd.Decoder):
    api_version = 3
    id = 'usb_standard_request'
    name = 'USB Standard Request'
    longname = 'USB Standard Request and Descriptor Decoder'
    desc = 'Decodes USB standard requests (Get Descriptor, Set Configuration, Set Interface, etc.) and parses descriptor contents.'
    license = 'gplv2+'
    inputs = ['usb_request']
    outputs = ['usb_standard_request']
    tags = ['PC']
    annotations = (
        ('request-name', 'Request name'),
        ('request-details', 'Request details'),
        ('descriptor-type', 'Descriptor type'),
        ('descriptor-header', 'Descriptor header'),
        ('descriptor-field', 'Descriptor field'),
        ('descriptor-string', 'String descriptor'),
        ('error', 'Error'),
    )
    annotation_rows = (
        ('requests', 'Standard Requests', (0, 1)),
        ('descriptors', 'Descriptors', (2, 3, 4, 5)),
        ('errors', 'Errors', (6,)),
    )

    def __init__(self):
        self.reset()

    def reset(self):
        self.pending_request = None
        # Store string index mappings from device descriptor
        # Format: {index: 'string_type'} e.g. {1: 'Manufacturer', 2: 'Product', 3: 'Serial Number'}
        self.string_index_map = {}
        # Store accumulated descriptor data for multi-packet transfers
        # Format: {(addr, ep, wValue, wIndex): {'data': bytearray, 'wLength': int, 'ss': int, 'es': int}}
        self.accumulated_descriptors = {}

    def start(self):
        self.out_ann = self.register(srd.OUTPUT_ANN)
        self.out_python = self.register(srd.OUTPUT_PYTHON)

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

    def is_standard_request(self, bmRequestType):
        """Check if this is a standard request."""
        return (bmRequestType & USB_REQ_TYPE_MASK) == USB_REQ_TYPE_STANDARD

    def get_request_name(self, bRequest):
        """Get human-readable request name."""
        return REQUEST_NAMES.get(bRequest, 'UNKNOWN (0x%02X)' % bRequest)

    def get_descriptor_type_name(self, desc_type):
        """Get human-readable descriptor type name."""
        if desc_type in DESCRIPTOR_NAMES:
            return DESCRIPTOR_NAMES[desc_type]
        # Check for class-specific descriptors (0x20-0x3F)
        if 0x20 <= desc_type <= 0x3F:
            base_type = desc_type & 0x0F
            base_name = DESCRIPTOR_NAMES.get(base_type, 'Unknown')
            return 'Class-specific %s (0x%02X)' % (base_name, desc_type)
        # Check for vendor-specific descriptors (0x40-0xFF)
        elif 0x40 <= desc_type <= 0xFF:
            return 'Vendor-specific (0x%02X)' % desc_type
        else:
            return 'Unknown (0x%02X)' % desc_type

    def parse_device_descriptor(self, data, ss, es):
        """Parse USB Device Descriptor."""
        if len(data) < 2:
            self.puta(ss, es, 6, ['Device Descriptor: Too short (%d bytes)' % len(data)])
            return
        
        bLength = data[0]
        bDescriptorType = data[1]
        
        # Check if this is actually a device descriptor
        if bDescriptorType != USB_DT_DEVICE:
            self.puta(ss, es, 6, ['Not a Device Descriptor (type: 0x%02X)' % bDescriptorType])
            return
        
        # Parse available fields - display as multi-line when hovered
        fields = []
        
        if len(data) >= 4:
            bcdUSB = struct.unpack('<H', data[2:4])[0]
            fields.append('USB Version: %d.%02d' % (bcdUSB >> 8, bcdUSB & 0xFF))
        
        if len(data) >= 8:
            bDeviceClass = data[4]
            bDeviceSubClass = data[5]
            bDeviceProtocol = data[6]
            bMaxPacketSize0 = data[7]
            fields.append('Device Class: 0x%02X' % bDeviceClass)
            fields.append('Device SubClass: 0x%02X' % bDeviceSubClass)
            fields.append('Device Protocol: 0x%02X' % bDeviceProtocol)
            fields.append('Max Packet Size: %d' % bMaxPacketSize0)
        
        if len(data) >= 12:
            idVendor = struct.unpack('<H', data[8:10])[0]
            idProduct = struct.unpack('<H', data[10:12])[0]
            fields.append('Vendor ID: 0x%04X' % idVendor)
            fields.append('Product ID: 0x%04X' % idProduct)
        
        if len(data) >= 14:
            bcdDevice = struct.unpack('<H', data[12:14])[0]
            fields.append('Device Version: %d.%02d' % (bcdDevice >> 8, bcdDevice & 0xFF))
        
        if len(data) >= 17:
            iManufacturer = data[14]
            iProduct = data[15]
            iSerialNumber = data[16]
            # Store string index mappings for later use
            if iManufacturer > 0:
                self.string_index_map[iManufacturer] = 'Manufacturer'
            if iProduct > 0:
                self.string_index_map[iProduct] = 'Product'
            if iSerialNumber > 0:
                self.string_index_map[iSerialNumber] = 'Serial Number'
            fields.append('Manufacturer String Index: %d' % iManufacturer)
            fields.append('Product String Index: %d' % iProduct)
            fields.append('Serial Number String Index: %d' % iSerialNumber)
        
        if len(data) >= 18:
            bNumConfigurations = data[17]
            fields.append('Number of Configurations: %d' % bNumConfigurations)
        
        if fields:
            # Multi-line text for hover (most detailed)
            multi_line = '\n'.join(fields)
            # Single-line summary for direct display (shortest)
            short_summary = ', '.join(fields[:3]) if len(fields) > 3 else ', '.join(fields)
            # Order: most detailed first (hover), shortest last (direct display)
            self.puta(ss, es, 4, [multi_line, short_summary])

    def parse_config_descriptor(self, data, ss, es):
        """Parse USB Configuration Descriptor."""
        if len(data) < 2:
            self.puta(ss, es, 6, ['Configuration Descriptor: Too short (%d bytes)' % len(data)])
            return
        
        bLength = data[0]
        bDescriptorType = data[1]
        
        # Check if this is actually a configuration descriptor
        if bDescriptorType != USB_DT_CONFIG:
            self.puta(ss, es, 6, ['Not a Configuration Descriptor (type: 0x%02X)' % bDescriptorType])
            return
        
        # Parse available fields - display as multi-line when hovered
        fields = []
        fields.append('CONFIGURATION DESCRIPTOR')
        fields.append('\tbLength: %d | bDescriptorType: 0x%02X (CONFIGURATION)' % (bLength, bDescriptorType))
        
        if len(data) >= 4:
            wTotalLength = struct.unpack('<H', data[2:4])[0]
            fields.append('\twTotalLength: %d' % wTotalLength)
        
        if len(data) >= 9:
            bNumInterfaces = data[4]
            bConfigurationValue = data[5]
            iConfiguration = data[6]
            bmAttributes = data[7]
            bMaxPower = data[8]
            fields.append('\tbNumInterfaces: %d | bConfigurationValue: %d | iConfiguration: %d' % 
                        (bNumInterfaces, bConfigurationValue, iConfiguration))
            
            # Decode bmAttributes - compact format
            attr_parts = []
            if bmAttributes & 0x40:
                attr_parts.append('SELF-POWERED')
            else:
                attr_parts.append('NOT SELF-POWERED')
            if bmAttributes & 0x20:
                attr_parts.append('REMOTE-WAKEUP')
            else:
                attr_parts.append('NO REMOTE-WAKEUP')
            fields.append('\tConfiguration bmAttributes: 0x%02X (%s)' % (bmAttributes, ', '.join(attr_parts)))
            fields.append('\tbMaxPower: %d (%dmA)' % (bMaxPower, bMaxPower * 2))
        
        # Parse nested descriptors (Interface, Endpoint, etc.) and collect detailed info
        if len(data) > 9:
            offset = 9
            while offset < len(data):
                if offset + 2 > len(data):
                    break
                desc_len = data[offset]
                desc_type = data[offset + 1]
                
                if desc_len == 0:
                    break
                
                # Validate descriptor length
                if desc_len < 2:
                    break
                
                if offset + desc_len > len(data):
                    desc_len = len(data) - offset
                
                desc_data = data[offset:offset + desc_len]
                
                if desc_type == USB_DT_INTERFACE:
                    # Parse interface descriptor and add details to config descriptor
                    if len(desc_data) >= 9:
                        if_num = desc_data[2]
                        alt_setting = desc_data[3]
                        num_eps = desc_data[4]
                        if_class = desc_data[5]
                        if_subclass = desc_data[6]
                        if_protocol = desc_data[7]
                        iInterface = desc_data[8]
                        
                        # Determine class name
                        class_names = {
                            0x01: 'Audio',
                            0x02: 'Communications',
                            0x03: 'HID',
                            0x07: 'Printing',
                            0x08: 'Mass Storage',
                            0x0E: 'Video',
                            0x0F: 'Personal Healthcare',
                            0x10: 'Audio/Video',
                            0x11: 'USB Type-C Bridge',
                            0xDC: 'Diagnostic Device',
                            0xE0: 'Wireless Controller',
                            0xEF: 'Miscellaneous',
                            0xFE: 'Application Specific',
                            0xFF: 'Vendor Specific',
                        }
                        class_name = class_names.get(if_class, '')
                        
                        fields.append('INTERFACE DESCRIPTOR (%d.%d): class %s' % (if_num, alt_setting, class_name if class_name else 'Unknown'))
                        fields.append('\tbLength: %d | bDescriptorType: 0x%02X (INTERFACE)' % (desc_len, desc_type))
                        fields.append('\tbInterfaceNumber: %d | bAlternateSetting: %d | bNumEndpoints: %d' % 
                                    (if_num, alt_setting, num_eps))
                        fields.append('\tbInterfaceClass: %s (0x%02X) | bInterfaceSubClass: 0x%02X | bInterfaceProtocol: 0x%02X | iInterface: %d' % 
                                    (class_name if class_name else 'Unknown', if_class, if_subclass, if_protocol, iInterface))
                
                elif desc_type == USB_DT_ENDPOINT:
                    # Parse endpoint descriptor and add details to config descriptor
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
                        
                        transfer_names = ['Control', 'Isochronous', 'Bulk', 'Interrupt']
                        sync_names = ['None', 'Asynchronous', 'Adaptive', 'Synchronous']
                        usage_names = ['Data-Endpoint', 'Feedback-Endpoint', 'Implicit-Feedback-Data-Endpoint', 'Reserved']
                        
                        fields.append('ENDPOINT DESCRIPTOR')
                        fields.append('\tbLength: %d | bDescriptorType: 0x%02X (ENDPOINT)' % (desc_len, desc_type))
                        fields.append('\tbEndpointAddress: 0x%02X (%s Endpoint:%d)' % (ep_addr, ep_dir, ep_num))
                        fields.append('\tbmAttributes: 0x%02X (%s-Transfer, %s, %s)' % 
                                    (bm_attrs, transfer_names[transfer_type], sync_names[sync_type], usage_names[usage_type]))
                        if len(desc_data) >= 9:
                            bRefresh = desc_data[7] if len(desc_data) > 7 else 0
                            bSynchAddress = desc_data[8] if len(desc_data) > 8 else 0
                            fields.append('\twMaxPacketSize: %d | bInterval: %d | bRefresh: %d | bSynchAddress: %d' % 
                                        (wMaxPacketSize, bInterval, bRefresh, bSynchAddress))
                        else:
                            fields.append('\twMaxPacketSize: %d | bInterval: %d' % (wMaxPacketSize, bInterval))
                
                else:
                    # Skip class-specific descriptors (0x24 CS_INTERFACE, 0x25 CS_ENDPOINT, etc.)
                    # These should be handled by class-specific decoders
                    if desc_type in (0x24, 0x25):
                        # Skip class-specific descriptors - don't display them
                        pass
                    else:
                        # Handle other non-standard descriptors (vendor-specific, etc.)
                        desc_name = self.get_descriptor_type_name(desc_type)
                        fields.append('%s' % desc_name.upper())
                        fields.append('\tbLength: %d | bDescriptorType: 0x%02X' % (desc_len, desc_type))
                        # Show hex dump for unknown/class-specific descriptors
                        hex_str = ' '.join(['%02X' % b for b in desc_data[:min(16, len(desc_data))]])
                        if len(desc_data) > 16:
                            hex_str += '...'
                        fields.append('\tData: %s' % hex_str)
                
                offset += desc_len
        
        # Output configuration descriptor annotation with nested descriptor summary
        if fields:
            # Multi-line text for hover (most detailed)
            multi_line = '\n'.join(fields)
            # Single-line summary for direct display (shortest)
            short_summary = 'CONFIGURATION DESCRIPTOR (%d interfaces)' % (bNumInterfaces if len(data) >= 9 else 0)
            # Order: most detailed first (hover), shortest last (direct display)
            self.puta(ss, es, 4, [multi_line, short_summary])

    def parse_interface_descriptor(self, data, ss, es):
        """Parse USB Interface Descriptor."""
        if len(data) < 2:
            self.puta(ss, es, 6, ['Interface Descriptor: Too short (%d bytes)' % len(data)])
            return
        
        bLength = data[0]
        bDescriptorType = data[1]
        
        # Check if this is actually an interface descriptor
        if bDescriptorType != USB_DT_INTERFACE:
            self.puta(ss, es, 6, ['Not an Interface Descriptor (type: 0x%02X)' % bDescriptorType])
            return
        
        # Parse available fields - display as multi-line when hovered
        fields = []
        
        if len(data) >= 5:
            bInterfaceNumber = data[2]
            bAlternateSetting = data[3]
            bNumEndpoints = data[4]
            fields.append('Interface Number: %d' % bInterfaceNumber)
            fields.append('Alternate Setting: %d' % bAlternateSetting)
            fields.append('Number of Endpoints: %d' % bNumEndpoints)
        
        if len(data) >= 9:
            bInterfaceClass = data[5]
            bInterfaceSubClass = data[6]
            bInterfaceProtocol = data[7]
            iInterface = data[8]
            fields.append('Interface Class: 0x%02X' % bInterfaceClass)
            fields.append('Interface SubClass: 0x%02X' % bInterfaceSubClass)
            fields.append('Interface Protocol: 0x%02X' % bInterfaceProtocol)
            if iInterface > 0:
                fields.append('Interface String Index: %d' % iInterface)
        
        if fields:
            # Multi-line text for hover (most detailed)
            multi_line = '\n'.join(fields)
            # Single-line summary for direct display (shortest)
            short_summary = ', '.join(fields[:2]) if len(fields) > 2 else ', '.join(fields)
            # Order: most detailed first (hover), shortest last (direct display)
            self.puta(ss, es, 4, [multi_line, short_summary])

    def parse_endpoint_descriptor(self, data, ss, es):
        """Parse USB Endpoint Descriptor."""
        if len(data) < 2:
            self.puta(ss, es, 6, ['Endpoint Descriptor: Too short (%d bytes)' % len(data)])
            return
        
        bLength = data[0]
        bDescriptorType = data[1]
        
        # Check if this is actually an endpoint descriptor
        if bDescriptorType != USB_DT_ENDPOINT:
            self.puta(ss, es, 6, ['Not an Endpoint Descriptor (type: 0x%02X)' % bDescriptorType])
            return
        
        # Parse available fields - display as multi-line when hovered
        fields = []
        
        if len(data) >= 4:
            bEndpointAddress = data[2]
            bmAttributes = data[3]
            ep_num = bEndpointAddress & 0x0F
            ep_dir = 'IN' if (bEndpointAddress & 0x80) else 'OUT'
            transfer_type = bmAttributes & 0x03
            transfer_names = ['Control', 'Isochronous', 'Bulk', 'Interrupt']
            fields.append('Endpoint Address: %d (%s)' % (ep_num, ep_dir))
            fields.append('Transfer Type: %s' % transfer_names[transfer_type])
        
        if len(data) >= 7:
            wMaxPacketSize = struct.unpack('<H', data[4:6])[0]
            bInterval = data[6]
            fields.append('Max Packet Size: %d' % wMaxPacketSize)
            fields.append('Polling Interval: %d' % bInterval)
        
        if fields:
            # Multi-line text for hover (most detailed)
            multi_line = '\n'.join(fields)
            # Single-line summary for direct display (shortest)
            short_summary = ', '.join(fields[:2]) if len(fields) > 2 else ', '.join(fields)
            # Order: most detailed first (hover), shortest last (direct display)
            self.puta(ss, es, 4, [multi_line, short_summary])

    def parse_string_descriptor(self, data, ss, es, index=0):
        """Parse USB String Descriptor."""
        if len(data) < 2:
            self.puta(ss, es, 6, ['String Descriptor: Too short (%d bytes)' % len(data)])
            return
        
        bLength = data[0]
        bDescriptorType = data[1]
        
        # Check if this is actually a string descriptor
        if bDescriptorType != USB_DT_STRING:
            self.puta(ss, es, 6, ['Not a String Descriptor (type: 0x%02X)' % bDescriptorType])
            return
        
        # Determine string type based on index from device descriptor
        string_type = self.string_index_map.get(index, None)
        if string_type:
            string_label = '%s String (Index %d)' % (string_type, index)
        else:
            string_label = 'String Descriptor (Index %d)' % index
        
        # Handle partial data - don't treat it as an error
        # String descriptors contain UTF-16LE encoded strings
        if len(data) > 2:
            # Use available data, not necessarily full length
            string_bytes = data[2:len(data)]
            
            # Special case: Language ID descriptor (index 0)
            # Contains language IDs as UTF-16LE words
            if index == 0 or (len(string_bytes) == 2 and string_bytes[0] < 0x20):
                # This is likely a language ID descriptor
                language_ids = []
                for i in range(0, len(string_bytes), 2):
                    if i + 1 < len(string_bytes):
                        lang_id = struct.unpack('<H', string_bytes[i:i+2])[0]
                        language_ids.append('0x%04X' % lang_id)
                fields = []
                fields.append('%s (%d bytes, received %d)' % (string_label, bLength, len(data)))
                if language_ids:
                    fields.append('Language IDs: %s' % ', '.join(language_ids))
                multi_line = '\n'.join(fields)
                short_summary = 'Language IDs: %s' % ', '.join(language_ids) if language_ids else string_label
                self.puta(ss, es, 3, [multi_line, short_summary])
                return
            
            # Convert UTF-16LE to string
            try:
                # Ensure we have even number of bytes for UTF-16LE
                if len(string_bytes) % 2 == 1:
                    string_bytes = string_bytes[:-1]
                if len(string_bytes) > 0:
                    string_text = string_bytes.decode('utf-16-le')
                    fields = []
                    fields.append('%s (%d bytes, received %d)' % (string_label, bLength, len(data)))
                    fields.append('String: "%s"' % string_text)
                    multi_line = '\n'.join(fields)
                    if string_type:
                        short_summary = '%s: "%s"' % (string_type, string_text)
                    else:
                        short_summary = 'String: "%s"' % string_text
                    self.puta(ss, es, 3, [multi_line, short_summary])
                else:
                    self.puta(ss, es, 3, ['%s (%d bytes, received %d)' % (string_label, bLength, len(data))])
            except:
                # Fallback: show hex
                hex_str = ' '.join(['%02X' % b for b in string_bytes])
                fields = []
                fields.append('%s (%d bytes, received %d)' % (string_label, bLength, len(data)))
                fields.append('String (hex): %s' % hex_str)
                multi_line = '\n'.join(fields)
                if string_type:
                    short_summary = '%s (hex): %s' % (string_type, hex_str)
                else:
                    short_summary = 'String (hex): %s' % hex_str
                self.puta(ss, es, 3, [multi_line, short_summary])
        else:
            # Only header bytes received
            self.puta(ss, es, 3, ['%s (%d bytes, received %d)' % (string_label, bLength, len(data))])

    def decode_standard_request(self, setup, data, ss, es, request=None):
        """Decode a standard USB request."""
        bmRequestType = setup['bmRequestType']
        bRequest = setup['bRequest']
        wValue = setup['wValue']
        wIndex = setup['wIndex']
        wLength = setup['wLength']
        
        # Store setup_data for output
        setup_data_bytes = None
        if request is not None:
            setup_data_bytes = request.get('setup_data')
        if setup_data_bytes is None:
            # Reconstruct setup packet from setup dict
            setup_data_bytes = bytearray(8)
            setup_data_bytes[0] = bmRequestType
            setup_data_bytes[1] = bRequest
            setup_data_bytes[2:4] = struct.pack('<H', wValue)
            setup_data_bytes[4:6] = struct.pack('<H', wIndex)
            setup_data_bytes[6:8] = struct.pack('<H', wLength)
        
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
        
        # Build annotation with setup request details - single text only
        if bRequest == USB_REQ_GET_DESCRIPTOR:
            desc_type = (wValue >> 8) & 0xFF
            desc_index = wValue & 0xFF
            # Handle case where wValue format might be different (e.g., 0x0003 for string descriptor)
            # For wValue=0x0003, if desc_type=0x00 but data shows string descriptor, treat as string
            if desc_type == 0x00 and desc_index > 0:
                # This might be a string descriptor request with non-standard wValue format
                # Show as string descriptor request
                if desc_index == 0:
                    desc_name = 'String (Language IDs)'
                else:
                    desc_name = 'String (Index %d)' % desc_index
                self.puta(ss, es, 0, ['GET DESCRIPTOR %s (wValue: 0x%04X, Length: %d)' % 
                                      (desc_name, wValue, wLength)])
            else:
                desc_name = self.get_descriptor_type_name(desc_type)
                self.puta(ss, es, 0, ['GET DESCRIPTOR %s (Type: 0x%02X, Index: %d, Length: %d)' % 
                                      (desc_name.upper(), desc_type, desc_index, wLength)])
        elif bRequest == USB_REQ_SET_DESCRIPTOR:
            desc_type = (wValue >> 8) & 0xFF
            desc_index = wValue & 0xFF
            desc_name = self.get_descriptor_type_name(desc_type)
            self.puta(ss, es, 0, ['SET DESCRIPTOR %s (Type: 0x%02X, Index: %d, Length: %d)' % 
                                  (desc_name.upper(), desc_type, desc_index, wLength)])
        elif bRequest == USB_REQ_SET_CONFIGURATION:
            config_value = wValue & 0xFF
            # Show detailed information
            fields = []
            fields.append('SET CONFIGURATION')
            fields.append('Configuration Value: %d' % config_value)
            if config_value == 0:
                fields.append('Status: Unconfigured')
            else:
                fields.append('Status: Configured')
            multi_line = '\n'.join(fields)
            short_summary = 'SET CONFIGURATION (Value: %d)' % config_value
            self.puta(ss, es, 0, [multi_line, short_summary])
        elif bRequest == USB_REQ_GET_CONFIGURATION:
            self.puta(ss, es, 0, ['GET CONFIGURATION'])
        elif bRequest == USB_REQ_SET_INTERFACE:
            interface_num = wIndex & 0xFF
            alt_setting = wValue & 0xFF
            # Show detailed information
            fields = []
            fields.append('SET INTERFACE')
            fields.append('Interface Number: %d' % interface_num)
            fields.append('Alternate Setting: %d' % alt_setting)
            multi_line = '\n'.join(fields)
            short_summary = 'SET INTERFACE (Interface: %d, Alternate Setting: %d)' % (interface_num, alt_setting)
            self.puta(ss, es, 0, [multi_line, short_summary])
        elif bRequest == USB_REQ_GET_INTERFACE:
            interface_num = wIndex & 0xFF
            self.puta(ss, es, 0, ['GET INTERFACE (Interface: %d)' % interface_num])
        elif bRequest == USB_REQ_SET_ADDRESS:
            address = wValue & 0x7F
            # Show detailed information
            fields = []
            fields.append('SET ADDRESS')
            fields.append('Device Address: %d' % address)
            if address == 0:
                fields.append('Status: Default Address')
            else:
                fields.append('Status: New Address')
            multi_line = '\n'.join(fields)
            short_summary = 'SET ADDRESS (Address: %d)' % address
            self.puta(ss, es, 0, [multi_line, short_summary])
        elif bRequest == USB_REQ_GET_STATUS:
            self.puta(ss, es, 0, ['GET STATUS'])
        elif bRequest == USB_REQ_CLEAR_FEATURE:
            self.puta(ss, es, 0, ['CLEAR FEATURE'])
        elif bRequest == USB_REQ_SET_FEATURE:
            self.puta(ss, es, 0, ['SET FEATURE'])
        elif bRequest == USB_REQ_SYNCH_FRAME:
            self.puta(ss, es, 0, ['SYNCH FRAME'])
        else:
            self.puta(ss, es, 0, ['%s (wValue: 0x%04X, wIndex: 0x%04X, wLength: %d)' % 
                                  (req_name.replace('_', ' '), wValue, wIndex, wLength)])
        
        # Parse descriptor data if this is a GET_DESCRIPTOR request/response with data
        if bRequest == USB_REQ_GET_DESCRIPTOR and len(data) > 0:
            desc_type = (wValue >> 8) & 0xFF
            desc_index = wValue & 0xFF
            # Check actual descriptor type in data if desc_type from wValue is 0x00
            # This handles cases where wValue format might be different (e.g., 0x0003 for string descriptor)
            if desc_type == 0x00 and len(data) >= 2:
                actual_desc_type = data[1]
                if actual_desc_type == USB_DT_STRING:
                    # This is a string descriptor, use wValue low byte as index
                    # For wValue=0x0003, index=3, but data shows language ID (index 0 special case)
                    # Actually, wValue=0x0003 might mean type=0x03, index=0x00 (swapped)
                    # Or it could be a non-standard format where type is in low byte
                    # Let's use the actual index from wValue low byte
                    self.parse_string_descriptor(data, ss, es, desc_index)
                    return
            elif desc_type == USB_DT_DEVICE:
                self.parse_device_descriptor(data, ss, es)
            elif desc_type == USB_DT_CONFIG:
                self.parse_config_descriptor(data, ss, es)
            elif desc_type == USB_DT_STRING:
                desc_index = wValue & 0xFF
                self.parse_string_descriptor(data, ss, es, desc_index)
            elif desc_type == USB_DT_INTERFACE:
                self.parse_interface_descriptor(data, ss, es)
            elif desc_type == USB_DT_ENDPOINT:
                self.parse_endpoint_descriptor(data, ss, es)
            else:
                self.puta(ss, es, 2, ['%s Descriptor (%d bytes)' % 
                                     (self.get_descriptor_type_name(desc_type), len(data))])
        
        # Handle SET_ADDRESS response - no separate message needed, details already shown in request
        
        # Handle SET_CONFIGURATION response - no separate message needed, details already shown in request
        
        # Handle SET_INTERFACE response - no separate message needed, details already shown in request
        
        # Handle GET_INTERFACE response
        if bRequest == USB_REQ_GET_INTERFACE and len(data) == 1:
            alt_setting = data[0]
            interface_num = wIndex & 0xFF
            fields = []
            fields.append('GET INTERFACE Response')
            fields.append('Interface Number: %d' % interface_num)
            fields.append('Alternate Setting: %d' % alt_setting)
            multi_line = '\n'.join(fields)
            short_summary = 'Alternate Setting: %d' % alt_setting
            self.puta(ss, es, 1, [multi_line, short_summary])
        
        # Handle GET_CONFIGURATION response
        if bRequest == USB_REQ_GET_CONFIGURATION and len(data) == 1:
            config_value = data[0]
            fields = []
            fields.append('GET CONFIGURATION Response')
            fields.append('Configuration Value: %d' % config_value)
            if config_value == 0:
                fields.append('Status: Unconfigured')
            else:
                fields.append('Status: Configured')
            multi_line = '\n'.join(fields)
            short_summary = 'Configuration Value: %d' % config_value
            self.puta(ss, es, 1, [multi_line, short_summary])
        
        # Output standard request for higher-level decoders
        if request is not None:
            request_data = {
                'type': request.get('type', 'SETUP IN'),
                'addr': request.get('addr', 0),
                'ep': request.get('ep', 0),
                'setup_data': bytes(setup_data_bytes) if setup_data_bytes else None,
                'data': bytes(data) if data else b'',
                'handshake': request.get('handshake', ''),
            }
            self.put(ss, es, self.out_python, ['REQUEST', request_data])

    def decode(self, ss, es, data):
        ptype, pdata = data
        
        if ptype != 'REQUEST':
            return
        
        request = pdata
        request_type = request['type']
        setup_data = request['setup_data']
        data_bytes = request['data']
        
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
            self.puta(ss, es, 6, ['Invalid setup packet'])
            return
        
        # Check if this is a standard request
        is_standard = self.is_standard_request(setup['bmRequestType'])
        if not is_standard:
            # Not a standard request, but output it for higher-level decoders (e.g., UAC)
            # Output class-specific or vendor-specific requests
            request_data = {
                'type': request_type,
                'addr': request['addr'],
                'ep': request['ep'],
                'setup_data': bytes(setup_data) if setup_data else None,
                'data': bytes(data_bytes) if data_bytes else b'',
                'handshake': request.get('handshake', ''),
            }
            self.put(ss, es, self.out_python, ['CLASS_REQUEST', request_data])
            return  # Not a standard request, skip standard processing
        
        # Handle GET_DESCRIPTOR requests that may span multiple packets
        # usb_request decoder may output multiple REQUEST events for multi-packet transfers
        # We need to accumulate them ourselves
        bRequest = setup['bRequest']
        wValue = setup['wValue']
        wIndex = setup['wIndex']
        wLength = setup['wLength']
        
        if bRequest == USB_REQ_GET_DESCRIPTOR and request_type == 'SETUP IN' and wLength > 0:
            # Create a unique key for this descriptor request
            request_key = (request['addr'], request['ep'], wValue, wIndex)
            
            if request_key in self.accumulated_descriptors:
                # Accumulate data from this packet
                acc = self.accumulated_descriptors[request_key]
                acc['data'].extend(data_bytes)
                acc['es'] = es  # Update end sample
                
                # Check if we have received all data
                if len(acc['data']) >= acc['wLength']:
                    # We have complete data, parse it
                    complete_data = bytes(acc['data'][:acc['wLength']])
                    self.decode_standard_request(setup, complete_data, acc['ss'], acc['es'], request)
                    # Remove from accumulated dict
                    del self.accumulated_descriptors[request_key]
                elif len(acc['data']) >= 2:
                    # Check if this looks like a complete descriptor
                    # For string descriptors, device may return less than wLength
                    desc_type_from_data = acc['data'][1]
                    desc_len_from_data = acc['data'][0]
                    if desc_type_from_data == USB_DT_STRING and len(acc['data']) >= desc_len_from_data:
                        # String descriptor appears complete, parse it
                        complete_data = bytes(acc['data'][:desc_len_from_data])
                        self.decode_standard_request(setup, complete_data, acc['ss'], acc['es'], request)
                        del self.accumulated_descriptors[request_key]
                # Otherwise, continue accumulating (don't output anything yet)
            else:
                # First packet of this descriptor request
                # Start accumulating
                self.accumulated_descriptors[request_key] = {
                    'data': bytearray(data_bytes),
                    'wLength': wLength,
                    'ss': ss,
                    'es': es,
                }
                # Check if we already have complete data in first packet
                if len(data_bytes) >= wLength:
                    # Single packet, parse immediately
                    complete_data = bytes(data_bytes[:wLength])
                    self.decode_standard_request(setup, complete_data, ss, es, request)
                    del self.accumulated_descriptors[request_key]
                elif len(data_bytes) >= 2:
                    # Check if this looks like a complete descriptor
                    # For string descriptors, device may return less than wLength
                    desc_type_from_data = data_bytes[1]
                    desc_len_from_data = data_bytes[0]
                    if desc_type_from_data == USB_DT_STRING and len(data_bytes) >= desc_len_from_data:
                        # String descriptor appears complete, parse it
                        complete_data = bytes(data_bytes[:desc_len_from_data])
                        self.decode_standard_request(setup, complete_data, ss, es, request)
                        del self.accumulated_descriptors[request_key]
                    # Otherwise, continue accumulating (will parse when complete)
                # Otherwise, continue accumulating (will parse when complete)
        else:
            # Not a multi-packet GET_DESCRIPTOR, decode normally
            self.decode_standard_request(setup, data_bytes, ss, es, request)
