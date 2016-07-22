"""FlexNet text configuration file."""

import re
import StringIO
import shlex

# http://media.3ds.com/support/simulia/public/flexlm108/EndUser/chap10.htm

FLEXNET_LINES = ["USE_SERVER",
                 "SERVER",
                 "VENDOR",
                 "DAEMON",
                 "INCREMENT",
                 "FEATURE",
                 "UPGRADE",
                 "PACKAGE"] 

def flexnet_parse(text):
    lines = _flexnet_lex(text)
    entries = _flexnet_parse(lines)
    return entries

def _flexnet_lex(text):
    text = text.replace('\r\n', '\n')
    text = text.replace('\\\n', '')
    lines = []
    for line in text.split('\n'):
        line = re.sub(r'\s+', ' ', line)
        lines.append([])
        str_file = StringIO.StringIO(line)
        lex = shlex.shlex(str_file)
        lex.wordchars += ".,-/:;+^"
        token = lex.get_token()
        while token != lex.eof:
            lines[-1].append(token)
            token = lex.get_token()
    lines = filter(len, lines)
    return lines

def _flexnet_parse(lines):
    entries = {"servers": [], "vendors": [], "use_server": False, "licenses": [] }
    for line in lines:
        if line[0] == 'USE_SERVER':
            entries['use_server'] = True
        elif line[0] == 'SERVER':
            server = {}
            server['host'] = line[1]
            server['hostid'] = line[2]
            opts = line[3:]
            while len(opts) and opts[0] == '=':
                server['hostid'] += opts.pop(0)
                server['hostid'] += opts.pop(0)
            if len(opts):
                server['port'] = int(opts[0])
            entries['servers'].append(server)
        elif line[0] == 'VENDOR' or line[0] == 'DAEMON':
            vendor = {}
            vendor['vendor'] = line[1]
            if len(line)>2:
                vendor['vendor_daemon_path'] = line[2]
            entries['vendors'].append(vendor)
        elif line[0] == 'INCREMENT' or line[0] == 'FEATURE':
            lic = {}
            lic['feature']  = line[1]
            lic['vendor']   = line[2]
            lic['version']  = line[3]
            lic['expdate']  = line[4]
            if line[5] == 'uncounted':
                lic['quantity'] = 0
            else: 
                lic['quantity'] = int(line[5])
            # NOTE: The parsing gets too easily confused with the extra entries
            opts = line[6:]
            while opts.count('=') > 0:
                i = opts.index('=')
                val = opts.pop(i+1).strip('"')
                opts.pop(i)
                key = opts.pop(i-1).strip('"').lower()
                while len(opts)>1 and opts[1] == '=':
                    val += opts.pop(1)
                    val += opts.pop(1)
                lic[key] = val
            if len(opts) > 0:
                lic['others'] = opts
            entries['licenses'].append(lic)
    return entries
