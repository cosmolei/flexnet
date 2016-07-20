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
import pycrc

import flexnet.file

HEADERLEN = 20
TYPE_REQLIC1 = 0x004e
TYPE_REQ     = 0x0108
TYPE_HELLO   = 0x010e
TYPE_STUBR   = 0x0113
TYPE_REQLIC2 = 0x0114
TYPE_STUB2   = 0x0128
TYPE_STUB    = 0x013b
TYPE_REQLIC  = 0x013c
TYPE_RESP    = 0x0146
HEADERLENS = {}
HEADERLENS[TYPE_REQLIC1] = 20
HEADERLENS[TYPE_REQ]     = 22
HEADERLENS[TYPE_HELLO]   = 24
HEADERLENS[TYPE_STUBR]   = 20
HEADERLENS[TYPE_REQLIC2] = 20
HEADERLENS[TYPE_STUB2]   = 20
HEADERLENS[TYPE_STUB]    = 24
HEADERLENS[TYPE_REQLIC]  = 20
HEADERLENS[TYPE_RESP]    = 24
PREFIXES = [0x2f, 0x4c, 0x4e]

# Protocol changed around version 11.10
VER_NEW = (11, 10)

CRCWIDTH = 14
CRCPOLY = 0x2e97
crc = pycrc.Crc(width=CRCWIDTH, poly=CRCPOLY, reflect_in=True, xor_in=0, reflect_out=True, xor_out=0)

class FlexNetClient():

    def __init__(self, server, port=None):
        if port is None:
            port, server = server.split('@')
            port = int(port)

        self.server   = server # server hostname for TCP connections
        self.port     = port   # server port number for TCP connections
        self.debug    = False  # show raw binary sent and received
        self.verbose  = False  # show parsed messages received
        self.oldproto = None   # will be set later if server version < VER_NEW

        self.user    = os.environ['USER']
        self.host    = socket.gethostname()
        self.vendor  = "" # empty to start, then vendor name
        self.tty     = '/dev/pts/1'
        self.pid     = str(os.getpid())
        self.arch    = 'x64_lsb' # OS/arch ("64-bit Linux Standard Base"?)
        self.version = (11,11) # "this" lmstat version

        self.server_params = {}

        self.connect()

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
        for vendor in p["vendors"].keys():
            v = p["vendors"][vendor]
            print('vendor %s at %s@%s' % (vendor, v["port"], v["hostname"]))
            print()
            print('Features:')
            for feature in v["features"]:
                print("   %s" % feature)
            print('Licenses:')
            for lic in v["licenses"]:
                print()
                for key in lic.iterkeys():
                    print("%-15s%s" % (key, lic[key]))
            if p.has_key("license_sets"):
                for i in range(len(p["license_sets"])):
                    lic = p["license_sets"][i]
                    print('  License Set %d:' % i)
                    for key in lic.iterkeys():
                        print("      %s: %s" % (key, lic[key]))

    def query_server(self):
        """Make initial connection and query main server details"""
        msg = self.hello()
        self.server_params["server_hostname"] = msg["hostname"]
        self.server_params["server_daemon"]   = msg["daemon"]
        self.server_params["server_version"]  = msg["server_version"]

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
        self.server_params["licenses"] = parsed_lic_file["licenses"]
        return parsed_lic_file

    def query_vendor_list(self):
        """Get list of all vendor names"""
        msg = self.request("dlist")
        txt = msg["text"][0].strip()
        vendor_names = txt.split()
        self.server_params["vendors"] = {key: {} for key in vendor_names}
        return vendor_names

    def query_vendor_details(self):
        """Connect to each vendor daemon for full details"""
        vendors = self.server_params["vendors"]
        for vendor in vendors.keys():
            self.vendor = vendor
            msg = self.hello()
            vendors[vendor]["hostname"] = msg["vendor_hostname"]
            vendors[vendor]["port"] = msg["vendor_port"]
        for vendor in vendors.keys():
            self.close()
            # get more data from other port
            self.server = msg["vendor_hostname"]
            self.port = msg["vendor_port"]
            self.connect()
            self.hello()
            vendors[vendor]["features"] = self.query_vendor_features()
            vendors[vendor]["licenses"] = {}
            # TODO make it work for oldproto
            if not self.oldproto:
                vendors[vendor]["licenses"] = self.query_vendor_licenses()
            for license in vendors[vendor]["licenses"]:
                license["status"] = self.query_vendor_license_status(license["parsed"])
        return vendors

    # These methods require a connection to a vendor daemon first

    def query_vendor_features(self):
        """Query a vendor daemon for a list of available features"""
        if self.oldproto:
            msg = self.stub_old('\x3d\xda\x6c\x31')
        else:
            msg = self.stub()
        features = msg["text"][0].split()
        return features

    def query_vendor_licenses(self):
        """Query a vendor daemon for full license details"""
        msg = self.stub(data='\x01\x00\x00\x00\x00', reqtype=0x0127)
        # Sometimes this will have a garbage whitespace entry.
        # Remove those before continuing.
        msg["text"] = filter(lambda x: not re.match('^\s*$', x), msg["text"])
        num = len(msg["text"])/8
        license_sets =[{} for x in range(num)]
        keys = ["fid", "sig", "names", "date1", "date2", "fid", "url", "text"]
        for i in range(len(msg["text"])):
            lic = license_sets[i/8]
            lic[keys[i%8]] = msg["text"][i]
        for lic in license_sets:
            # NOTE: assuming there's only ever one license entry here.  Is that
            # reasonable?
            lic["parsed"] = flexnet.file.flexnet_parse(lic["text"])["licenses"][0]
        return license_sets

    def query_vendor_license_status(self, lic):
        """Query a vendor daemon for current usage on a license"""
        feature = lic["feature"]
        sig = lic.get("SIGN")
        if not sig:
            sig = lic["others"][0]
        if self.oldproto:
            req = feature.ljust(31, '\x00') + sig.ljust(21, '\x00') + '1'
            cb = (sum(map(ord, req))+108)%256
            req = '\x6c' + chr(cb) + req
            req = req.ljust(147, '\x00')
            response = self._query(req)
            # Cadence... these should probably go on the previous usage entry?
            # ugly, ugly, ugly
            while ord(response[0]) != 0x4e:
                lics = self.server_params["licenses"]
                response = self._query(req)
                idx = lics.index(lic)-1
                #lics[idx]["status"]["usage"].append(response)
            msg = self._request_parse(response)
            status = {}
            status["used"] = int(msg["text"][0])
            status["total"] = int(msg["text"][1])
            status["timestamp"] = time.gmtime(int(msg["text"][2]))
        else:
            req = '\x00'.join([feature, sig[:20]]) + '\x00'*4 + '\x01'
            msg = self.stub(data=req, reqtype=TYPE_REQLIC)
            data = filter(len, msg["text"])
            status = {}
            status["used"] = int(data[0][2:])
            status["total"] = int(data[1])
            status["timestamp"] = time.gmtime(int(data[2]))
        status["usage"] = []
        for i in range(status["used"]):
            response = self._query()
            status["usage"].append(response)
        # Cadence...
        #if self.oldproto:
        #    self.close()
        #    self.connect()
        return status

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
        """Send introductory message to main server"""
        req = self._hello_pack()
        response = self._query(req)
        return self._request_parse(response)

    def request(self, command=""):
        """Send a request with a specified command to main server

        Commands I know of are:
           (blank)  - fetch license file contents
           dlist    - fetch vendor names
           getpaths - fetch license file path relative to daemon installation
        """
        req = self._request_pack(command)
        response = self._query(req)
        return self._request_parse(response)

    def stub_old(self, data):
        """Send a request to a vendor daemon (older protocol)"""
        req = data.ljust(147, '\x00')
        response = self._query(req)
        return self._request_parse(response)

    def stub(self, data='\x31\x00\x30\x00', reqtype=TYPE_STUB):
        """Send a request to a vendor daemon"""
        req = self._header_create(data, reqtype) + data
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
        # redirect message, to point to a different port and possibly a
        # different host altogether.  This follows a hello() with a vendor
        # specified.
        elif header.get("type") == TYPE_STUBR:
            payload = response[header["len"]:]
            hostname, remainder = payload.split('\x00', 1)
            message["vendor_hostname"] = hostname
            message["vendor_port"], = struct.unpack('!L', remainder[:4])
        elif header.get("type") == TYPE_STUB2:
            # The "text" is interspersed with runs of NULLs and 0x01 and 0x07.
            # No idea what that means.
            txt = response[header["len"]:]
            strip_binary = lambda x: x.strip('\x01\x07')
            fields = filter(len, map(strip_binary, txt.split('\x00')))
            message["text"] = fields
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
