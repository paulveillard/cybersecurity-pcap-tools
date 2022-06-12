#Sanicap

A python based packet capture sanitizer

##Features
* Clean your pcaps for worry-free sharing
* Can randomize/sequentialize:
    * MAC addresses
    * IPv4/IPv6 addresses
* Integrates with scapy, pyshark, cloud-pcap

##Installation
`setup.py` file coming soon. For now, copy to directory of your project.

Scapy can be a pain to install and get running due to dependencies not available via pip, but the best documentation for it is here: [Scapy Installation](http://www.secdev.org/projects/scapy/doc/installation.html)

##Usage

#### In another python script
    >>> from sanicap import sanitize
	>>> sanicap.sanitize('/path/to/test.pcap', sequential=True, ipv4_mask=8, ipv6_mask=16)
     This file has 23 IPv4/IPv6 endpoints and 6 MAC endpoints
     File created: /path/to/test_sanitized_141205-124237.pcap

#### As a CLI utility
    $ python sanicap.py -h
    usage: sanicap.py [-h] [-o FILEPATH_OUT] [-s SEQUENTIAL] [--ipv4mask IPV4MASK]
                      [--ipv6mask IPV6MASK] [--macmask MACMASK]
                      [--startipv4 STARTIPV4] [--startipv6 STARTIPV6]
                      [--startmac STARTMAC]
                      filepath_in
    $ python sanicap.py test.pcap -s True --ipv4mask=8
    This file has 23 IPv4/IPv6 endpoints and 6 MAC endpoints
    File created: test_sanitized_141206-091251.pcap

##ToDo
* Add pcapng support
* standalone CLI usage
* Anonymize DNS Queries
* Anonymize HTTP host info
* Anonymize HTTP data? (not sure what yet, maybe just POST data)
* python BPF capture filter (apply to pcap files)