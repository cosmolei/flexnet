"""Network client for FlexNet license management protocol. """

from __future__ import print_function

import os
import sys
import socket
import struct
import time
import calendar
import binascii
import re
import copy
import pycrc

import flexnet.file

HEADERLEN = 20
TYPE_REQLIC1 = 0x004e # response: license status (vendor)
TYPE_REQ     = 0x0108 # request: command (manager)
TYPE_HELLO   = 0x010e # response: hello
TYPE_STUBR   = 0x0113 # response: hello w/ vendor set (manager)
TYPE_REQLIC2 = 0x0114 # response: license usage (vendor)
TYPE_LICSET  = 0x0127 # request: vendor's licenses (vendor)
TYPE_STUB2   = 0x0128 # response: vendor's licenses (vendor)
TYPE_STUB    = 0x013b # request: vendor's features (vendor)
TYPE_REQLIC  = 0x013c # request: license status (vendor)
TYPE_RESP    = 0x0146 # response: command (manager)
HEADERLENS = {}
HEADERLENS[TYPE_REQLIC1] = 20
HEADERLENS[TYPE_HELLO]   = 24
HEADERLENS[TYPE_STUBR]   = 20
HEADERLENS[TYPE_REQLIC2] = 20
HEADERLENS[TYPE_STUB2]   = 20
HEADERLENS[TYPE_RESP]    = 24
PREFIXES = [0x2f, 0x4c, 0x4e]

# Protocol changed around version 11.10
VER_NEW = (11, 10)

CRCWIDTH = 14
CRCPOLY = 0x2e97
crc = pycrc.Crc(width=CRCWIDTH, poly=CRCPOLY, reflect_in=True, xor_in=0, reflect_out=True, xor_out=0)

class _Client(object):
    """Base class for both server types"""

    def __init__(self, server, port=None):
        if port is None:
            port, server = server.split('@')
            port = int(port)

        self.server   = server # server hostname for TCP connections
        self.port     = port   # server port number for TCP connections
        self.debug    = False  # show raw binary sent and received
        self.verbose  = False  # show parsed messages received
        self.oldproto = None   # will be set later if server version < VER_NEW

        self.user    = os.environ.get('USER') or ''
        self.host    = socket.gethostname()
        self.vendor  = "" # empty to start, then vendor name
        self.tty     = '/dev/pts/1'
        self.pid     = str(os.getpid())
        self.arch    = 'x64_lsb' # OS/arch ("64-bit Linux Standard Base"?)
        self.version = (11,11) # "this" lmstat version

        self.connect()

    # Lower-level public methods for specific connection and request types

    def connect(self):
        """Open TCP connection to self.server at self.port"""
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(10)
        self.s.connect((self.server, self.port))

    def close(self):
        """Close TCP connection"""
        self.s.close()

    def hello(self):
        """Send introductory message to license manager server"""
        req = self._hello_pack()
        response = self._query(req)
        return self._request_parse(response)

    # Implementation details

    def _hello_pack(self):
        data = ( self.user.ljust(20,   '\x00'),
                 self.host.ljust(32,   '\x00'),
                 self.vendor.ljust(10, '\x00'),
                 self.tty.ljust(32,    '\x00'),
                 '\x84'.ljust(12,      '\x00'), # ???
                 self.pid.ljust(10,    '\x00'),
                 self.arch.ljust(12,   '\x00') )

        ver = struct.pack("BB", *self.version)
        num = '78\x0014\x00' # ???
        req = ''.join([d+'\x00' for d in data]) + ver + num

        cb = sum(map(ord, req[:len(req)-2]))%256
        prefix = struct.pack('4B', 0x68, # ???
                                   cb,
                                   0x31, # ???
                                   0x33) # ???
        req = prefix + req
        return req

    # TODO many of these response types only occur for certain requests.
    # Refactor this to separate them and move things to the other classes where
    # needed.
    def _request_parse(self, response):
        header = self._header_parse(response)
        message = {}
        message["header"] = header

        # Old version, chunked text data

        if header["prefix"] == 0x4c:
            resp_text = ""
            for i in range(0, len(response), 147):
                resp_text += response[i+13:i+147]
            resp_text = resp_text.strip('\x00').split('\x00')
            message["text"] = resp_text

        # Otherwise newer version

        # response to a hello() request
        elif header.get("type") == TYPE_HELLO:
            txt = response[header["len"]:].strip('\x00').split('\x00')
            message["hostname"]        = txt[0]
            message["daemon"]          = txt[1]
            message["server_version"]  = header["srv_ver"]
            ver = header["srv_ver"]
            ver = ver[0] << 8 | ver[1]
            if ver < ((VER_NEW[0]<<8) | VER_NEW[1]):
                self.oldproto = True

        # What I'm calling STUBR (stub response) here actually looks like a
        # redirect message, to point to a vendor daemon running on a different
        # port and possibly a different host altogether.  This follows a
        # hello() with a vendor specified.
        elif header.get("type") == TYPE_STUBR:
            payload = response[header["len"]:]
            hostname, remainder = payload.split('\x00', 1)
            message["vendor_hostname"] = hostname
            message["vendor_port"], = struct.unpack('!L', remainder[:4])

        # Response to request for license sets?
        elif header.get("type") == TYPE_STUB2:
            # The "text" is interspersed with runs of NULLs and 0x01 and 0x07.
            # No idea what that means.
            txt = response[header["len"]:]
            strip_binary = lambda x: x.strip('\x01\x07')
            fields = filter(len, map(strip_binary, txt.split('\x00')))
            message["text"] = fields

        # Response to license status request.
        elif header.get("type") == TYPE_REQLIC1:
            payload = response[header["len"]:]
            # mysterious 2-byte prefix, followed by ASCII integers for number
            # used, number in total, and a timestamp.
            prefix    = struct.unpack('BB', payload[0:2])
            fields = filter(len, payload[2:].split('\x00'))
            used      = fields[0]
            total     = fields[1]
            timestamp = fields[2]
            message["prefix"]    = prefix
            message["used"]      = int(used)
            message["total"]     = int(total)
            message["timestamp"] = time.gmtime(int(timestamp))

        # Response showing license usage following a license status request.
        # One response per group reservation/user chckout for that license.
        elif header.get("type") == TYPE_REQLIC2:
            segments = response[header["len"]:].split('\x01',1)
            # null-terminated strings
            txtfields = segments[0].split('\x00')
            # group reservations are handled separately.  They have an extra
            # 'G' at the beginning of the name field and zeros for the binary
            # segment.
            if not sum(map(ord,segments[1])) and txtfields[0][0] == 'G':
                message["group_reservation"] = txtfields[0][1:]
            else:
                message["user"]    = txtfields[0]
                message["host"]    = txtfields[1]
                message["tty"]     = txtfields[2]
                message["version"] = txtfields[3]
                # remaining bytes of binary data
                timestamp = segments[1][4:8]
                number    = segments[1][8:16]
                timeval, = struct.unpack('!L', timestamp)
                message["time"] = time.gmtime(timeval)
                message["number"], = struct.unpack('!Q', number)

        else:
            txt = response[header["len"]:].strip('\x00').split('\x00')
            fields = filter(len, txt)
            message["text"] = fields

        if self.verbose:
            sys.stderr.write("Parsed Response:\n")
            for key in message.keys():
                sys.stderr.write("   %s: %s\n" % (key, str(message[key])))
        return message

    def _header_create(self, data, reqtype=TYPE_REQ):
        # The length of the entire request in bytes, for TYPE_REQ, will be:
        # --- 20 byte prefix + header
        # 4 for the prefix (0x2f + checkbyte + crc)
        # 8 for the header (req len + req type + timestamp)
        # 8 null-padding
        # --- Message
        # 2 for \x01\x04 (what's this?)
        # a varying-length segment with the main data
        # ---
        timestamp = calendar.timegm(time.gmtime()) # Current unix time in UTC
        reqlen = len(data)+HEADERLEN
        # The 18 bytes before prefix, checksum, CRC
        header = struct.pack("!HHL",
                reqlen,
                reqtype,
                timestamp)
        header = header.ljust(16, '\x00')

        return chr(0x2f) + self._checkbytes(header+data) + header
    
    def _checkbytes(self, data):
        # CRC is packed in 2 bytes, big-endian
        crc_val = crc.table_driven(map(ord, data))
        crc_str = struct.pack("!H", crc_val)
        # check byte is a modular sum of of the header data
        cb = (sum(map(ord, crc_str + data[:16]))+47)%256
        return chr(cb) + crc_str

    def _header_parse(self, data):
        header = {}
        header["prefix"],   = struct.unpack('B', data[0])
        if header["prefix"] == 0x4c:
            return header
        if header["prefix"] == 0x4e:
            header["len"] = 2
            return header
        header["checksum"], = struct.unpack('B', data[1])
        header["crc"],      = struct.unpack('!H', data[2:4])
        header["msg_len"],  = struct.unpack('!H', data[4:6])
        header["type"],     = struct.unpack('!H', data[6:8])
        header["len"] = HEADERLENS[header["type"]]
        if header["type"] == TYPE_HELLO:
            header["token"],  = struct.unpack('!L', data[8:12])
            header["srv_ver"] = struct.unpack('2B', data[20:22])
            header["suffix"], = struct.unpack('!H', data[22:24])
        elif header["type"] == TYPE_RESP:
            timeval, = struct.unpack('!L', data[8:12])
            header["time"] = time.gmtime(timeval)
            header["txt_len"], = struct.unpack('!H', data[22:24])
        elif header["type"] == TYPE_REQLIC2:
            timeval, = struct.unpack('!L', data[8:12])
            header["time"] = time.gmtime(timeval)
        self._header_validate(data, header)
        return header

    def _header_validate(self, data, header):
        check = self._checkbytes(data[4:])
        if check != data[1:4]:
            check = binascii.hexlify(check)
            actual = binascii.hexlify(data[1:4])
            raise ValueError("Header prefix expected to be 0x%s, but got 0x%s" % (check, actual))

    def _query(self, request=None):
        if request:
            if self.debug:
                sys.stderr.write("Request: %s\n" % binascii.hexlify(request))
            self.s.sendall(request)
        response = self.s.recv(1)
        prefix = ord(response[0])
        if prefix not in PREFIXES:
            raise Exception("Unexpected response prefix %s" % hex(prefix))
        ### Older versions, data chunked in 147-byte segments
        if prefix == 0x4c:
            response += self.s.recv(147-1)
            length_remaining = self._length_remaining(response)
            while length_remaining > (147-13):
                newbytes = self.s.recv(147)
                while len(newbytes) < 147:
                    newbytes += self.s.recv(147-len(newbytes))
                response += newbytes
                length_remaining = self._length_remaining(newbytes)
        elif prefix == 0x4e:
            response += self.s.recv(147-1)
        ### Newer versions, length is given in header
        else:
            while len(response) < 20:
                response += self.s.recv(20-len(response))
            len_total, = struct.unpack('!H', response[4:6])
            torecv = len_total - len(response)
            # Now get remaining data
            while torecv>0:
                response += self.s.recv(min(4096, torecv))
                torecv = len_total - len(response)
        if self.debug:
            sys.stderr.write("Response: %s\n" % binascii.hexlify(response))
        return response

    def _length_remaining(self, data):
            return int(data[2:13].split('\x00')[0])


class ManagerClient(_Client):
    """A connection to a license manager daemon.

    This will follow redirects to managers running on other hosts if necessary.
    """

    def __init__(self, server, port=None):
        super(ManagerClient, self).__init__(server, port)
        self.vendors = [] # Vendor daemon connections via VendorClient()
        # TODO turn these into real attributes
        self.server_params = {}

    def query_everything(self):
        """Query server for all available information from all vendors"""
        # get initial data at the given port
        self.query_server()
        self.query_server_license_file_path()
        self.query_server_license_file_contents()
        self.query_vendor_list()
        # Connect to each vendor port for full details
        self.query_vendor_details()

    def report_everything(self):
        """Query everything and print results to standard output"""
        self.query_everything()
        p = self.server_params
        print('Server hostname:   %s'    % p["server_hostname"])
        print('Server daemon:     %s'    % p["server_daemon"])
        print('Server version:    %s.%s' % p["server_version"])
        print('License File Path: %s'    % p ["license_file_path"])
        print('Vendor daemons:    %s'    % ', '.join(p["vendors"]))
        print('License File:')
        print(p["license_file_text"])
        for vendor in self.vendors:
            print()
            print('vendor %s at %s@%s' % (vendor.vendor, vendor.port, vendor.server))
            print()
            print('Features:')
            for feature in vendor.features:
                print("   %s" % feature)
            print()
            print('   Licenses:')
            lics = vendor.licenses[::]
            for lic_set in vendor.license_sets:
                lics.extend(lic_set.licenses)
            for lic in lics:
                print(lic.report())
                print()
            print('   License Sets:')
            for lic_set in vendor.license_sets:
                print(lic_set.report())
                print()

    def query_server(self):
        """Make initial connection and query license manager details"""
        msg = self.hello()
        self.server_params["server_hostname"] = msg["hostname"]
        self.server_params["server_daemon"]   = msg["daemon"]
        self.server_params["server_version"]  = msg["server_version"]
        # For standalone managers that's all we need, but for redundant
        # managers it might be directing us to a different server entirely.
        # Either way just re-connecting with the specified hostname should
        # work.
        self.close()
        self.server = msg["hostname"]
        self.connect()
        self.hello()

    def query_server_license_file_path(self):
        """Query server for filesystem path to license file"""
        msg = self.request("getpaths")
        license_file_path = msg["text"][0]
        self.server_params["license_file_path"] = license_file_path
        return license_file_path

    def query_server_license_file_contents(self):
        """Query server for contents of license file text"""
        msg = self.request()
        self.server_params["license_file_text"] = msg["text"][0]
        parsed_lic_file = flexnet.file.flexnet_parse(msg["text"][0])
        self.server_params["licenses_in_file"] = parsed_lic_file["licenses"]
        return parsed_lic_file

    def query_vendor_list(self):
        """Get list of all vendor names"""
        msg = self.request("dlist")
        txt = msg["text"][0].strip()
        self.server_params["vendors"] = txt.split()
        # TODO it's possible for vendors to be up that aren't part of this
        # list, for example ansys has a vendor running in the manager daemon
        # itself.  It works to query that as well, but should we?  If the
        # manager doesn't report it, is it technically associated with that
        # manager at all?  Watch a packet trace and lmstat output to see how
        # this is handled.
        return self.server_params["vendors"]

    def query_vendor_details(self):
        """Connect to each vendor daemon for full details"""
        p = self.server_params
        vendors = {}
        # Gather vendor hostnames and ports
        for vendor_name in p["vendors"]:
            self.vendor = vendor_name
            msg = self.hello()
            vendors[vendor_name] = {}
            vendors[vendor_name]["hostname"] = msg["vendor_hostname"]
            vendors[vendor_name]["port"] = msg["vendor_port"]
        # Connect to each vendor
        for vendor_name in vendors.keys():
            v = vendors[vendor_name]
            client = VendorClient(v["hostname"], v["port"])
            self.vendors.append(client)
            client.vendor = vendor_name
            client.hello()
            client.query_vendor_features()
            # These are licenses reported directly by the vendor daemon,
            # and not mentioned in the license file text from the license
            # manager daemon.
            # TODO make this work for oldproto
            if not self.oldproto:
                client.query_vendor_licenses()
            # Alternatively, some licenses may only be listed in the license
            # file text returned by the license manager.  So, also query
            # licenses from the file that match this vendor.
            license_file_entries = filter(lambda lic: lic["vendor"] == vendor_name, p["licenses_in_file"])
            client.licenses = [flexnet.licenses.License(data) for data in license_file_entries]
            # Now that all licenses for this vendor have been accounted for,
            # actually request license status/usage from the vendor daemon
            for lic_set in client.license_sets:
                for lic in lic_set.licenses:
                    client.query_vendor_license_status(lic)
            for lic in client.licenses:
                client.query_vendor_license_status(lic)
        return vendors

    def request(self, command=""):
        """Send a request with a specified command to license manager server

        Commands I know of are:
           (blank)  - fetch license file contents
           dlist    - fetch vendor names
           getpaths - fetch license file path relative to daemon installation
        """
        req = self._request_pack(command)
        response = self._query(req)
        return self._request_parse(response)

    def _request_pack(self, command=""):
        data = ( self.user,
                 self.host,
                 self.server_params["server_daemon"],
                 self.tty,
                 command )
        req = '\x01\x04' + ''.join([d+'\x00' for d in data])
        headerstr = self._header_create(req)
        req = headerstr + req
        return req


class VendorClient(_Client):
    """A connection to a license vendor daemon"""

    def __init__(self, server, port=None):
        super(VendorClient, self).__init__(server, port)
        self.license_sets = []
        self.licenses = []
        self.features = set()

    def query_vendor_features(self):
        """Query a vendor daemon for a list of available features"""
        if self.oldproto:
            msg = self._stub_old('\x3d\xda\x6c\x31')
        else:
            msg = self._stub()
        features = msg["text"][0].split()
        self.features.update(features)
        return features

    def query_vendor_licenses(self):
        """Query a vendor daemon for full license details"""
        msg = self._stub(data='\x01\x00\x00\x00\x00', reqtype=TYPE_LICSET)
        # Sometimes this will have a garbage whitespace entry.
        # Remove those before continuing.
        msg["text"] = filter(lambda x: not re.match('^\s*$', x), msg["text"])
        num = len(msg["text"])/8
        license_sets =[{} for x in range(num)]
        keys = ["fid", "sig", "names", "date1", "date2", "fid", "url", "license_text"]
        for i in range(len(msg["text"])):
            lic = license_sets[i/8]
            lic[keys[i%8]] = msg["text"][i]
        self.license_sets.extend([flexnet.licenses.LicenseSet(lic) for lic in license_sets])
        return license_sets

    # TODO this is broken on Cadence.
    def query_vendor_license_status(self, lic):
        """Query a vendor daemon for current status and usage on a license"""
        feature = lic.feature
        sign = lic.sign
        if not sign:
            sign = lic.others[0]

        # Query general status
        if self.oldproto:
            status = self._query_license_status_old(feature, sign)
        else:
            status = self._query_license_status(feature, sign)

        # Query usage.  Implicitly refers to last license that was checked; no
        # new request is sent.
        status["usage"] = []
        for i in range(status["used"]):
            response = self._query_license_usage()
            status["usage"].append(response)

        lic.status.update(status)
        return status

    def _query_license_status(self, feature, sign):
        """Query status on a single license by feature name and signature"""
        status = {}
        req = '\x00'.join([feature, sign[:20]]) + '\x00'*4 + '\x01'
        msg = self._stub(data=req, reqtype=TYPE_REQLIC)
        status["prefix"] = msg["prefix"]
        status["used"] = msg["used"]
        status["total"] = msg["total"]
        status["timestamp"] = msg["timestamp"]
        return status

    def _query_license_status_old(self, feature, sign):
        """Query status on a single license by feature name and signature (older version)"""
        status = {}
        req = feature.ljust(31, '\x00') + sign.ljust(21, '\x00') + '1'
        cb = (sum(map(ord, req))+108)%256
        req = '\x6c' + chr(cb) + req
        req = req.ljust(147, '\x00')
        response = self._query(req)

        # Cadence... these should probably go on the previous usage entry?
        # ugly, ugly, ugly
        while ord(response[0]) != 0x4e:
            lics = self.licenses
            response = self._query(req)
            #idx = lics.index(lic)-1
            #lics[idx].status["usage"].append(response)

        msg = self._request_parse(response)
        status["used"] = int(msg["text"][0])
        status["total"] = int(msg["text"][1])
        status["timestamp"] = time.gmtime(int(msg["text"][2]))
        return status

    def _query_license_usage(self):
        """Query usage details on the last license that was checked"""
        response = self._query()
        msg = self._request_parse(response)
        del msg["header"]
        return msg

    def _stub_old(self, data):
        """Send a general request to a vendor daemon (older protocol)"""
        req = data.ljust(147, '\x00')
        response = self._query(req)
        return self._request_parse(response)

    def _stub(self, data='\x31\x00\x30\x00', reqtype=TYPE_STUB):
        """Send a general request to a vendor daemon"""
        req = self._header_create(data, reqtype) + data
        response = self._query(req)
        return self._request_parse(response)
