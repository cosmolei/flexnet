# flexnet

A pure Python package for querying information from [FlexNet] license servers. 

This acts as a "read-only" client for real-time license status and usage
information, like the native `lmstat` binary provides.  See the `ManagerClient`
class in the `client` module for a starting point.  This is currently a tangled
mess of unfinished code, but I wanted to make sure it was available if it could
be helpful for others, as it does contain some details of the querying methods
for the FlexNet protocol I couldn't find anywhere else (before figuring them
out).

The intent was to create a tool to help with the centralized management of a
diverse set of license servers, possibly running on different hosts with
different license managers and versions (as this is currently a bit of a PITA).
This does _not_ attempt any "write" operations like checking out or releasing a
license.

## Experimental Methods

[tcpdump] and [Wireshark] were used to watch the plaintext messages to and from
servers from the proprietary clients, and the Python packages [scapy] and
[numpy] were used for analysis. The syntax was then reimplemented in Python
here.  [CRC RevEng] was used for finding the bit length, polynomial, and other
characteristics for the [Cyclic Redundacy Check][CRC] the protocol uses,
working with a set of captured packets.

[Netzob] looks like it would have been helpful, had I seen it sooner.

## Protocol

The messages transmitted and received are mainly plaintext mixed with numerical
data as chunks of raw binary.  The `_checkbytes` method of the `_Client` class
shows the checksumming technique used for most types of messages: a pair of CRC
bytes prepended to the message bytes, with a modular one-byte sum of all bytes
(including the CRC bytes) prepended to that.

## Dependencies

This depends on [pycrc](https://pycrc.org/) for calculating CRC values for
the transmitted messages.

[tcpdump]: http://www.tcpdump.org/
[Wireshark]: https://www.wireshark.org/
[CRC RevEng]: http://reveng.sourceforge.net/
[CRC]: https://en.wikipedia.org/wiki/Cyclic_redundancy_check
[scapy]: http://www.secdev.org/projects/scapy/
[numpy]: http://www.numpy.org/
[FlexNet]: https://en.wikipedia.org/wiki/FlexNet_Publisher
[Netzob]: https://www.netzob.org/
