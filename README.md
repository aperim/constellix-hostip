
![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)
![Dependencies](https://img.shields.io/badge/dependencies-up%20to%20date-brightgreen.svg)
[![GitHub Issues](https://img.shields.io/github/issues/aperim/constellix-hostip.svg)](https://github.com/aperim/constellix-hostip/issues)
![Contributions welcome](https://img.shields.io/badge/contributions-welcome-orange.svg)
[![License](https://img.shields.io/badge/license-CC0-blue.svg)](https://creativecommons.org/share-your-work/public-domain/cc0/)

## Basic Overview

Set the forward and reverse DNS entries for a host with DNS services provided by Constellix. Supports IPv6 and IPv4.

## Super Super Important

As you will see below - this is a slow, very painful process. Constellix's API sucks. If you can use any other DNS hosting service - do it - don't waste your time here. If you are stuck with constellix (like we are) and you find this script useful - great. Please contact constellix and ask them to take their API seriously.

## Docker
You can run this inside a docker container:
```bash
$ docker run --rm -it -e CONSTELLIX_APISECRET=690dfc33-e457-401e-a1c4-d4a2f1b870b7 -e CONSTELLIX_APIKEY=3a4ffdf9-71e4-4458-94b6-14fd940b81bf ghcr.io/aperim/constellix-hostip/constellix-hostip:latest -vvv example.com
```

## Environment
You must set your consetllix token details in two environment variables.
```bash
export CONSTELLIX_APISECRET=690dfc33-e457-401e-a1c4-d4a2f1b870b7 #Use your secret not this one
export CONSTELLIX_APIKEY=3a4ffdf9-71e4-4458-94b6-14fd940b81bf #Use your key not this one
```

## Setting records
```bash
python3 ./constellix/host.py --ipv4 203.0.113.1 --ipv6 2001:0db8:0000:0025:0000:0000:0000:0000 example.com
```
The above would set the following records:
`203.0.113.1 A example.com.`

`2001:0db8:0000:0025:0000:0000:0000:0000 AAAA example.com.`

`1.113.0.203.in-addr.arpa. PTR example.com.`

`0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa PTR example.com.`

## Deleting Records
```bash
python3 ./constellix/host.py example.com
```
Will delete and A, AAAA and PTR records that are set for example.com

## Command Line Arguments
```text
usage: host.py [-h] [-4 IPV4] [-6 IPV6] [-v] domain

positional arguments:
  domain                The domain name

optional arguments:
  -h, --help            show this help message and exit
  -4 IPV4, --ipv4 IPV4  The IPv4 address for the domain
  -6 IPV6, --ipv6 IPV6  The IPv6 address for the domain
  -v, --verbose (the more v's the more verbose)
```

## Assumptions
Forward and reverse records can only be set for domains in your account.

## Caveats
This is a slow process.
Constellix doesn't have any way to find a domain record with a simple search, so we have to look for parts of the domain until we find a match - for IPv6 records - this takes a lot of API requests.

### Speed

Further hindering the process is authentication errors with Constellix's API. Over 50% of valid API requests fail against the API with a `401` error. Once Constellix fix this - it will double the speed of these updates.
Constellix's API now take 20+ seconds to respond to most requests. Expect updating the forward and reverse records for one domain to take well in excess of 5½ minutes (sometimes up to 20).

*NOTE* Constellix have still note resolved this issue properly as at Dec 2022

## Examples

#### Output

```text
$ ./constellix/host.py -vvv --ipv6 2001:0db8:0000:0025:0000:0000:0000:0000 --ipv4 203.0.113.1  demo.example.com
2020-09-09 01:38:59 INFO     Getting details for domain demo.example.com.
2020-09-09 01:38:59 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=demo.example.com
2020-09-09 01:39:05 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=example.com
2020-09-09 01:39:08 INFO     [GET] https://api.dns.constellix.com/v1/domains/99990
2020-09-09 01:39:10 INFO     [GET] https://api.dns.constellix.com/v1/domains/99990/records/A/search?exact=test4
2020-09-09 01:39:15 INFO     [GET] https://api.dns.constellix.com/v1/domains/99990/records/AAAA/search?exact=test4
2020-09-09 01:39:18 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=1.113.0.203.in-addr.arpa
2020-09-09 01:39:19 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=113.0.203.in-addr.arpa
2020-09-09 01:39:19 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.203.in-addr.arpa
2020-09-09 01:39:20 INFO     [GET] https://api.dns.constellix.com/v1/domains/880880
2020-09-09 01:39:23 INFO     [GET] https://api.dns.constellix.com/v1/domains/880880/records/PTR/search?exact=1.113
2020-09-09 01:39:25 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:39:26 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:39:29 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.0.0.0.0.0.0.0.0.0.0.0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:39:31 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.0.0.0.0.0.0.0.0.0.0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:39:37 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.0.0.0.0.0.0.0.0.0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:39:41 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.0.0.0.0.0.0.0.0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:39:46 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.0.0.0.0.0.0.0.0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:39:49 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.0.0.0.0.0.0.0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:39:51 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.0.0.0.0.0.0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:39:54 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.0.0.0.0.0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:39:59 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.0.0.0.0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:40:02 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.0.0.0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:40:02 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.0.0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:40:04 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:40:09 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:40:17 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:40:23 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:40:25 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=5.2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:40:27 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=2.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:40:29 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:40:30 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:40:35 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:40:37 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:40:38 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:40:42 INFO     [GET] https://api.dns.constellix.com/v1/domains/search?exact=0.8.b.d.0.1.0.0.2.ip6.arpa
2020-09-09 01:40:45 INFO     [GET] https://api.dns.constellix.com/v1/domains/777000
2020-09-09 01:40:50 INFO     [GET] https://api.dns.constellix.com/v1/domains/777000/records/PTR/search?exact=0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.5.2.0.0.0.0.0
2020-09-09 01:40:58 INFO     [POST] https://api.dns.constellix.com/v1/domains/99990/records
2020-09-09 01:41:07 INFO     [POST] https://api.dns.constellix.com/v1/domains/880880/records
2020-09-09 01:41:10 INFO     [POST] https://api.dns.constellix.com/v1/domains/777000/records
2020-09-09 01:41:15 INFO     Completed processing in 136511ms.
4 records added. 
```

## Contributing
Please take a look at our [contributing](https://github.com/aperim/constellix-hostip/blob/master/CONTRIBUTING.md) guidelines if you're interested in helping!
#### Pending Features
- Let us know
