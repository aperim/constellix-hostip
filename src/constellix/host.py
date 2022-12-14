#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Update Constellix DNS with host and also set PTRs when possible.

Uses the `CONSTELLIX_APISECRET` and `CONSTELLIX_APIKEY` environment variables
to interact with the Constellix DNS API.

Sends updates to the Constellix API to set the forward records (A and AAAA)
and reverse (PTR) records for the host in question. Uses domain rationalisation
to find the parent domain when needed because Constellix's API doesn't
have the cocept of "search".

The Constellix API has an over 50% failure rate for API calls, so this
is very fault tollerant. You can tune it as you need, but I've found that
10 retries is the minimum to get reliable setting of forward and reverse
domain entries.

Environment Variables:
    The environment variables below must be set to the correct values to be
    able to connect to the Constellix API.

        `CONSTELLIX_APISECRET`: The API secret
        `CONSTELLIX_APIKEY`: The API key

Note:
    It takes a long time to find the parent domains for both forward
    and reverse entries, especially IPv6 because the Constellix API
    doesn't have an ability to search for a fully qualified domain name.

Examples:
    To create the forward and reverse DNS entries for the host
    `demo.sydney.example.com` with IPv4 address `172.16.1.100` and
    IPv6 address `fd34:fe56:7891:2f3a::1`

        $ python host.py -4 172.16.1.100 -6 fd34:fe56:7891:2f3a::1 \\
            demo.sydney.example.com

    To delete the host `demo.sydney.example.com` forward and reverse records
    simply do not provide any IPv4 or IPv6 addresses.

        $ python host.py demo.sydney.example.com

Todo:
    * Get Constellix to fix their API (Looks like it might finally be fixed!)

.. _Aperim:
   https://aperim.com/

"""

import logging
import datetime
import argparse
import re

import util
import dns

DEFAULT_TTL = 1800
"""int: The default TTL

The TTL used for newly created DNS entries
"""

def main():
    start_timestamp = datetime.datetime.now()

    parser = argparse.ArgumentParser()
    parser.add_argument("-4", "--ipv4", help="The IPv4 address for the domain", type=str)
    parser.add_argument("-6", "--ipv6", help="The IPv6 address for the domain", type=str)
    parser.add_argument('-v', '--verbose', action='count', default=0)
    parser.add_argument("domain", help="The domain name", type=str)
    args = parser.parse_args()

    _verbose = args.verbose
    if _verbose > 3:
        log_level = logging.DEBUG
    elif _verbose > 2:
        log_level = logging.INFO
    elif _verbose > 1:
        log_level = logging.WARNING
    elif _verbose > 0:
        log_level = logging.ERROR
    else:
        log_level = logging.CRITICAL

    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', level=log_level, datefmt='%Y-%m-%d %H:%M:%S')

    logging.info('Getting details for domain %s.', args.domain)
    
    domain = dns.Domain(args.domain,verbosity=_verbose)
    domain.deafult_ttl = DEFAULT_TTL
    domain.get_known_ptr()
    if args.ipv4: 
        ips = re.split(r',\s*|;\s*|\s+', args.ipv4)
        domain.add_update("A", ips)
    else:
        domain.add_update("A")
    if args.ipv6:
        ips = re.split(r',\s*|;\s*|\s+', args.ipv6)
        domain.add_update("AAAA", ips)
    else:
        domain.add_update("AAAA")
    domain.sync_ptr()
    changes = domain.sync()

    finish_timestamp = datetime.datetime.now()
    elapsed_time = finish_timestamp - start_timestamp
    elapsed_time_ms = int(elapsed_time.total_seconds() * 1000)
    logging.info('Completed processing in %ims.',elapsed_time_ms)
    finished_text = ""
    if int(changes["added"]) > 0:
        finished_text += str(changes["added"]) + ' records added. '
    if int(changes["updated"]) > 0:
        finished_text += str(changes["updated"]) + ' records updated. '
    if int(changes["deleted"]) > 0:
        finished_text += str(changes["deleted"]) + ' records deleted. '

    if len(finished_text) == 0:
        finished_text = 'No changes were made.'

    util.stdout(finished_text)


if __name__ == '__main__':
    main()

