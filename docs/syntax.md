# Filter expression syntax

## Valid fields

* tcp:           bool
* udp:           bool
* vlan:          bool 
* arp:           bool
* eth.addr:      byte-string | regex
* eth.dst:       byte-string | regex
* eth.src:       byte-string | regex
* eth.type:      number | list(number)
* ip.addr:       ip | net | list(ip | net)
* ip.dst:        ip | net | list(ip | net)
* ip.src:        ip | net | list(ip | net)
* vlan.id:       number | list(number)
* port:          number | list(number)
* srcport:       number | list(number)
* dstport:       number | list(number)
* payload:       byte-string | regex
* payload.len:   number | list(number)
* payload.u8:    byte-read (1 byte)
* payload.be16:  byte-read (2 bytes, big-endian)
* payload.le16:  byte-read (2 bytes, little-endian)
* payload.be32:  byte-read (4 bytes, big-endian)
* payload.le32:  byte-read (4 bytes, little-endian)
* payload.be64:  byte-read (8 bytes, big-endian)
* payload.le64:  byte-read (8 bytes, little-endian)

## Type explanation
    
### bool

use the fields name with or without logical operations. 

Example:
* 'tcp'
* 'not udp'
* '!arp'

### byte-string

hexadecimal numbers separated by ':'.

Example:
* 'eth.src contains db:03 || eth.dst contains 00:55'
* 'payload contains 00:aa:bb:cc'

### list (of anything)

space separated types between curly braces.

Example:
* 'srcport in {80, 443}'
* 'srcport not in {80, 443}'
* 'eth.dst in {00.11.22.44:55, 55:44:33:22:11:00}'

### ip

An ip.

Example:
* 'ip.dst == 1.1.1.1'
* 'ip.dst == 2606:4700:4700::1111',
* 'ip.dst >= 173.245.48.0 && ip.dst < 173.245.49.0',
* 'ip.src != 192.168.0.1'

### net

An ip network in prefix notation.
Example:
* 'ip.addr in {192.168.1.0/24}'
* 'ip.dst in {192.168.3.1, 10.0.0.0/8}'

### mac-address

A Mac address. Separated by either of ':', '-', '.' or continuous.

Example:
* eth.addr == 11:22:33:44:55:66
* eth.src == 11-22-33-44-55-66
* eth.dst == 112.233.445.566
* eth.src == 112233445566
 
### number

A whole non-negative number without fractions. `eth.type` additionally accepts
`0x`-prefixed hex literals (e.g. `0x88a4`), which is the usual way to write ethertypes.
Underscores may be used as visual separators between digits (e.g. `1_000`, `0xff_ff`),
but not at the start or end of the digit sequence, and not doubled (`1__2`).

Example:
* 'srcport in {22, 80}'
* 'srcport < 1024'
* 'payload.len > 50 and payload.len < 500'
* 'eth.type == 0x88a4'                 // EtherCAT
* 'eth.type in {0x0800, 0x86dd}'       // IPv4 or IPv6
  
### regex

A double quoted ascii string with Rust regex support.

(See here for details: https://docs.rs/regex/1.9.1/regex/#syntax)

Example:
* 'payload matches "GET /secret"'
* 'payload ~ "\r\n\x45\xdb"'
* 'payload ~ "GET /(secret|password)"'
* 'payload ~ "[[:ascii:]]{100}"' // matches any payload that has a 100 ascii characters in a row
* 'payload ~ "^\x00BOOM\x00"' // matches any payload that starts with null followed by BOOM followed by null  

### byte-read (numeric)

Read raw bytes from the payload as integers and compare them. Supports big-endian and little-endian byte order.

Available fields:
* payload.u8[offset]:    1 byte (no endianness)
* payload.be16[offset]:  2 bytes, big-endian
* payload.le16[offset]:  2 bytes, little-endian
* payload.be32[offset]:  4 bytes, big-endian
* payload.le32[offset]:  4 bytes, little-endian
* payload.be64[offset]:  8 bytes, big-endian
* payload.le64[offset]:  8 bytes, little-endian

The offset is a decimal byte offset from the start of the payload.

Both sides of the comparison support arithmetic expressions with `+` and `-`, and can reference `payload.len`, constants (decimal or `0x` hex), or other byte reads.

Example:
* 'payload.u8[0] == 0xff'
* 'payload.be16[0] == 0x0800'
* 'payload.le32[4] >= 100'
* 'payload.be32[0] == payload.len - 4'
* 'payload.be16[0] + payload.be16[2] == payload.le32[4]'
* 'payload.be16[0] == 0x0800 and payload.u8[9] == 6'

Common protocol header sizes useful for offset calculations:
* TCP header (minimum): 20 bytes
* UDP header: 8 bytes
* IPv4 header (minimum): 20 bytes

Example with header offsets:
* 'payload.be16[2] == payload.len + 20' # TCP length field equals payload length plus TCP header size
* 'payload.be16[4] == payload.len + 8' # UDP length field equals payload length plus UDP header size

If the byte read is out of bounds (offset + size > payload length), the clause evaluates to false.

## Operations

### Logical

* and ('and', '&&')
* or ('or', '||')
* not ('not', '!')
* grouping using parentheses ().
* Comparison: '==', '!=', '>', '>=', '<', '<='
* In (bytes): 'contains'
* In (list): 'in'
* Not in (list): 'not in'
* Regex: 'matches', '~'

Examples:
* 'ip.src == 192.168.1.7 || ip.dst == 1.2.3.4 && (srcport == 9 || dstport == 9)'
* 'eth.src == 3f:43:9a:2c:00:00 or eth.dst contains 2c:9a:bb'
* 'srcport in {80, 443}'
* 'srcport not in {80, 443}'
* 'payload contains "something"'
* 'payload.len > 50'
* 'payload ~ "(ASCII|\x22\x12)"'
* 'payload ~ "(?i)CaSeInSeNsItIvE"' # case insensitive match

## Field semantics

### Missing fields

If the caller does not supply a field value on the `Matcher` (e.g. never calls `.eth_type(...)`),
any clause that references that field evaluates to **false**. Negating such a clause with `not`
therefore evaluates to **true**. This is consistent across all fields — a clause can only match
data that was actually provided.

### eth.type — VLAN and QinQ frames

`eth.type` matches the value the caller passes to `Matcher::eth_type`. The library does not
parse raw frames; it is the caller's responsibility to decide which EtherType value to supply:

* **Untagged frames**: pass the outer EtherType directly (e.g. `0x0800` for IPv4).
* **IEEE 802.1Q (VLAN)**: the outer EtherType field is `0x8100` (TPID). To match on the
  encapsulated protocol, the caller must strip the VLAN tag and pass the inner EtherType.
  To match on "frame is VLAN-tagged", write `eth.type == 0x8100`.
* **QinQ (802.1ad)**: outer TPID is `0x88a8`. Same principle applies — pass whichever
  layer's EtherType is meaningful for the use case.
* **IEEE 802.3 length-field frames**: when the two-byte field carries a frame length (value
  ≤ 1500) rather than an EtherType (value ≥ 1536), callers should omit `.eth_type()` on
  the matcher. The `eth.type` clause will evaluate to false (no match), which is the safe
  default.
  