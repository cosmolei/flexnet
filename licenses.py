import flexnet.file

class LicenseSet(object):
    """A grouped set of licenses as returned from a vendor daemon."""

    def __init__(self, license_set_data):
        self.fid   = license_set_data["fid"]
        self.sig   = license_set_data["sig"]
        self.names = license_set_data["names"]
        self.date1 = license_set_data["date1"]
        self.date2 = license_set_data["date2"]
        self.url   = license_set_data["url"]

        text = license_set_data["license_text"]
        parsed_lics = flexnet.file.flexnet_parse(text)
        self.licenses = [License(lic) for lic in parsed_lics["licenses"]]

    def report(self):
        fmt = "%-15s: %s"
        lines = []
        lines.append(fmt % ("fid",   self.fid))
        lines.append(fmt % ("sig",   self.sig))
        lines.append(fmt % ("names", self.names))
        lines.append(fmt % ("date1", self.date1))
        lines.append(fmt % ("date2", self.date2))
        lines.append(fmt % ("url",   self.url))
        lines.append(fmt % ("licenses", len(self.licenses)))
        return '\n'.join(lines)


class License(object):
    """An individual license."""

    def __init__(self, license_data):
        # Required
        self.feature  = license_data["feature"]
        self.vendor   = license_data["vendor"]
        self.version  = license_data["version"]
        self.expdate  = license_data["expdate"]
        self.quantity = license_data["quantity"]
        # Optional
        self.notice   = license_data.get("notice")
        self.issued   = license_data.get("issued")
        self.start    = license_data.get("start")
        self.sign     = license_data.get("sign")
        self.others   = license_data.get("others")
        # Will be filled in by network client
        self.status = {}

    def report(self):
        fmt = "%-15s: %s"
        lines = []
        lines.append(fmt % ("feature",  self.feature))
        lines.append(fmt % ("vendor",   self.vendor))
        lines.append(fmt % ("version",  self.version))
        lines.append(fmt % ("expdate",  self.expdate))
        lines.append(fmt % ("quantity", self.quantity))
        lines.append(fmt % ("notice",   self.notice))
        lines.append(fmt % ("issued",   self.issued))
        lines.append(fmt % ("start",    self.start))
        lines.append(fmt % ("sign",     self.sign))
        lines.append("status")
        for key in self.status:
            lines.append("    " + fmt % (key, self.status[key]))
        return '\n'.join(lines)
