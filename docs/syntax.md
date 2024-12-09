# Filter expression syntax

## Valid fields

* tcp:           bool
* udp:           bool
* vlan:          bool 
* arp:           bool
* eth.addr:      byte-string | regex
* eth.dst:       byte-string | regex
* eth.src:       byte-string | regex
* ip.addr:       ip | net | list(ip | net)
* ip.dst:        ip | net | list(ip | net)
* ip.src:        ip | net | list(ip | net)
* vlan.id:       number | list(number)
* port:          number | list(number)
* srcport:       number | list(number)
* dstport:       number | list(number)
* payload:       byte-string | regex
* payload.len:   number | list(number)

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

A whole non-negative number without fractions

Example:
* 'srcport in {22, 80}'
* 'srcport < 1024'
* 'payload.len > 50 and payload.len < 500'
  
### regex

A double quoted ascii string with Rust regex support.

(See here for details: https://docs.rs/regex/1.9.1/regex/#syntax)

Example:
* 'payload matches "GET /secret"'
* 'payload ~ "\r\n\x45\xdb"'
* 'payload ~ "GET /(secret|password)"'
* 'payload ~ "[[:ascii:]]{100}"' // matches any payload that has a 100 ascii characters in a row
* 'payload ~ "^\x00BOOM\x00"' // matches any payload that starts with null followed by BOOM followed by null  

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
  