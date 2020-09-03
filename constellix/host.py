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
    * Get Constellix to fix their API

.. _Aperim:
   https://aperim.com/

"""

import logging
import datetime
import ipaddress
import sys
import argparse
import traceback

import util
import dns

DEFAULT_TTL = 1800
"""int: The default TTL

The TTL used for newly created DNS entries
"""

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class CreateRecordError(Error):
    """Exception raised for errors creating records.

    Attributes:
        record -- the domain record in question
        message -- explanation of the error
    """

    def __init__(self, record, message):
        self.record = record
        self.message = message


def check_value(values, check):
    value_list=[]
    for value in values:
        if isinstance(value, str):
            value_list.append(value)
        elif "disableFlag" in value and "value" in value and not value["disableFlag"]:
            value_list.append(value["value"])

    if not value_list:
        return False

    return check in value_list

def check_ip_value(values, check):
    value_list=[]
    for value in values:
        if isinstance(value, str):
            value_list.append(ipaddress.ip_address(value))
        elif "disableFlag" in value and "value" in value and not value["disableFlag"]:
            value_list.append(ipaddress.ip_address(value["value"]))

    if not value_list:
        return False

    return ipaddress.ip_address(check) in value_list
    
def get_domain_record(domain_id, subdomain, record_type):
    if not domain_id:
        return
    search_data = {
        "exact": subdomain
    }
    record_type = record_type.upper()
    record_data = api.search(f'{domain_id}/records/{record_type}/search', search_data)
    if not record_data:
        return
    return record_data[0]

def get_reverse_record(ip_address):
    ip=ipaddress.ip_address(ip_address)
    ptr=ip.reverse_pointer
    if not ptr:
        return
    parent_domain = get_domain(ptr)
    if not parent_domain:
        return
    record=get_domain_record(parent_domain["id"], parent_domain["subdomain"], "ptr")
    if not record:
        return {
            "ip": str(ip),
            "parentId": parent_domain["id"],
            "name": parent_domain["subdomain"]
        }
    return {
        "ip": str(ip),
        "id": record["id"],
        "parentId": parent_domain["id"],
        "name": record["name"]
    }

def get_forward_records(domain_id, subdomain):
    data = {
        "ptr": {}
    }
    a = get_domain_record(domain_id, subdomain, "a")
    a_data = None
    aaaa = get_domain_record(domain_id, subdomain, "aaaa")
    aaaa_data = None

    if a:
        a_data = api.get(domain_id, "A", a["id"])
    else:
        data["a"] = {
            "parentId": domain_id,
            "name": subdomain
        }

    if aaaa:
        aaaa_data = api.get(domain_id, "AAAA", aaaa["id"])
    else:
        data["aaaa"] = {
            "parentId": domain_id,
            "name": subdomain
        }
    
    if a_data:
        data["a"] = a_data
        data["ptr"]["ipv4"] = {}
        for ip in a_data["value"]:
            ip=str(ipaddress.ip_address(ip))
            data["ptr"]["ipv4"][ip] = get_reverse_record(ip)
    if aaaa_data:
        data["aaaa"] = aaaa_data
        data["ptr"]["ipv6"] = {}
        for ip in aaaa_data["value"]:
            ip=str(ipaddress.ip_address(ip))
            data["ptr"]["ipv6"][ip] = get_reverse_record(ip)
    return data

def create_forward(ip, domain_id, subdomain_name, subdomain_id = None):
    ip=ipaddress.ip_address(ip)
    if not ip:
        return
    
    if ip.version == 4:
        record_type = "A"
    elif ip.version == 6:
        record_type = "AAAA"
    else:
        return

    if subdomain_id:
        update_domain_data ={
            "recordOption": "roundRobin",
            "name": subdomain_name,
            "ttl": DEFAULT_TTL,
            "roundRobin": [
                {
                    "value": str(ip),
                    "disableFlag": False
                }
            ]
        }
        result = api.update(domain_id, record_type, subdomain_id, update_domain_data)
        if result:
            return api.get(domain_id,record_type,subdomain_id)
        return
    else:
        create_domain_data ={
            "name": subdomain_name,
            "ttl": DEFAULT_TTL,
            "roundRobin": [
                {
                    "value": str(ip),
                    "disableFlag": False
                }
            ]
        }
        result = api.create(domain_id, record_type, create_domain_data)
        if result:
            return result[0]
        return

def create_ptr(ip, domain):
    ip=ipaddress.ip_address(ip)
    if not domain.endswith("."):
        domain += "."
    ptr_parent_domain = get_domain(ip.reverse_pointer)
    if not ptr_parent_domain:
        return
    ptr_record_search=get_domain_record(ptr_parent_domain["id"], ptr_parent_domain["subdomain"], "ptr")
    if ptr_record_search:
        ptr_record = api.get(ptr_parent_domain["id"], "PTR", ptr_record_search["id"])
    if ptr_record_search and ptr_record:

        if check_value(ptr_record["value"], domain):
            return ptr_record

        update_domain_data ={
            "name": ptr_record["name"],
            "ttl": DEFAULT_TTL,
            "roundRobin": [
                {
                    "value": domain
                }
            ]
        }

        result = api.update(ptr_parent_domain["id"],"PTR", ptr_record["id"], update_domain_data)
        if result:
            return result
        return
    else:
        new_domain_data ={
            "name": ptr_parent_domain["subdomain"],
            "ttl": DEFAULT_TTL,
            "roundRobin": [
                {
                    "value": domain
                }
            ]
        }
        result = api.create(ptr_parent_domain["id"],"PTR", new_domain_data)
        if result:
            return result[0]
        return

def update_ptr(domain_name, new_ip, current_ptrs = None):
    if not current_ptrs:
        return create_ptr(new_ip, domain_name)

    if new_ip in current_ptrs:
        return current_ptrs[new_ip]

    delete_all_ptrs(current_ptrs)
    return create_ptr(new_ip, domain_name)

def delete_ptr(ptr):
    if not ("parentId" in ptr and "id" in ptr):
        return False
    result = api.delete(ptr["parentId"], "PTR", ptr["id"])
    if not result:
        return False
    return True

def delete_all_ptrs(ptrs):
    for ptr in ptrs:
        ptrs[ptr]["deleted"] = delete_ptr(ptrs[ptr])
    return ptrs

def update_forward(forward_data, ip):
    if "id" in forward_data:
        subdomain_id = forward_data["id"]
    else:
        subdomain_id = None

    if "value" in forward_data and len(forward_data["value"]) == 1 and check_ip_value(forward_data["value"], ip):
        return forward_data

    return create_forward(ip, forward_data["parentId"], forward_data["name"], subdomain_id)

def update_domain(domain_name, update_ipv4 = None, update_ipv6 = None, ):
    domain = get_domain(domain_name)
    if not domain:
        return
    forwards = get_forward_records(domain["id"], domain["subdomain"])

    if "ptr" in forwards and "ipv4" in forwards["ptr"]:
        current_ipv4_ptrs = forwards["ptr"]["ipv4"]
    else:
        current_ipv4_ptrs = None

    if "ptr" in forwards and "ipv6" in forwards["ptr"]:
        current_ipv6_ptrs = forwards["ptr"]["ipv6"]
    else:
        current_ipv6_ptrs = None

    if update_ipv4:
        update_ipv4=str(ipaddress.ip_address(update_ipv4))
        ptr_v4_response = update_ptr(domain_name, update_ipv4, current_ipv4_ptrs)
        if not ptr_v4_response:
            raise CreateRecordError(f'{domain_name} PTR {update_ipv4}','Unable to create the record')
        a_response = update_forward(forwards["a"], update_ipv4)
        if not a_response:
            raise CreateRecordError(f'{domain_name} A {update_ipv4}','Unable to create the record')
    else:
        if current_ipv4_ptrs:
            delete_all_ptrs(current_ipv4_ptrs)
        if 'a' in forwards and 'id' in forwards["a"]:
            if api.delete(forwards["a"]["parentId"], "A", forwards["a"]["id"]):
                a_response = {
                    "value": [
                        "DELETED"
                    ]
                }

    if update_ipv6:
        update_ipv6=str(ipaddress.ip_address(update_ipv6))
        ptr_v6_response=update_ptr(domain_name, update_ipv6, current_ipv6_ptrs)
        if not ptr_v6_response:
            raise CreateRecordError(f'{domain_name} PTR {update_ipv6}','Unable to create the record')
        aaaa_response = update_forward(forwards["aaaa"], update_ipv6)
        if not aaaa_response:
            raise CreateRecordError(f'{domain_name} AAAA {update_ipv6}','Unable to create the record')
    else:
        if current_ipv6_ptrs:
            delete_all_ptrs(current_ipv6_ptrs)
        if 'aaaa' in forwards and 'id' in forwards["aaaa"]:
            if api.delete(forwards["aaaa"]["parentId"], "AAAA", forwards["aaaa"]["id"]):
                aaaa_response = {
                    "value": [
                        "DELETED"
                    ]
                }

    data = {}

    if 'a_response' in locals() and 'value' in a_response:
        data["A"] = a_response["value"][0]

    if 'aaaa_response' in locals() and 'value' in aaaa_response:
        data["AAAA"] = aaaa_response["value"][0]

    if 'ptr_v4_response' in locals() and 'name' in ptr_v4_response:
        data["PTR_IPV4"] = ptr_v4_response["name"]

    if 'ptr_v6_response' in locals() and 'name' in ptr_v6_response:
        data["PTR_IPV6"] = ptr_v6_response["name"]

    return data

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
    domain.get_known_ptr()

    finish_timestamp = datetime.datetime.now()
    elapsed_time = finish_timestamp - start_timestamp
    elapsed_time_ms = int(elapsed_time.total_seconds() * 1000)
    logging.info('Completed processing in %ims.',elapsed_time_ms)


if __name__ == '__main__':
    main()

# if __name__ == '__main__':
#     start_timestamp = datetime.datetime.now()

#     parser = argparse.ArgumentParser()
#     parser.add_argument("-4", "--ipv4", help="The IPv4 address for the domain", type=str)
#     parser.add_argument("-6", "--ipv6", help="The IPv6 address for the domain", type=str)
#     parser.add_argument("-a4", "--arpa-ipv4", help="The IPv4 arpa PTR domain ie 61.10.in-addr.arpa", type=str)
#     parser.add_argument("-a6", "--arpa-ipv6", help="The IPv6 arpa PTR domain ie a.4.0.0.1.9.0.0.8.7.c.0.1.2.ip6.arpa", type=str)
#     parser.add_argument("-p", "--parent", help="The parent domain for the subdomain", type=str)
#     parser.add_argument('-v', '--verbose', action='count', default=0)
#     parser.add_argument("domain", help="The domain name", type=str)
#     args = parser.parse_args()

#     _verbose = args.verbose
#     api.verbosity = args.verbose

#     try:
#         result = update_domain(args.domain, args.ipv4, args.ipv6)
#     except CreateRecordError as err:
#         util.stderr('Failed to create records:', err)
#         sys.exit(2)
#     except:
#         exc_info = sys.exc_info()
#         traceback.print_exception(*exc_info)
#         del exc_info
#         sys.exit(2)

#     finish_timestamp = datetime.datetime.now()
#     elapsed_time = finish_timestamp - start_timestamp
#     elapsed_time_ms = int(elapsed_time.total_seconds() * 1000)

#     if _verbose > 1:
#         util.jsd(result)
#     if _verbose > 0:
#         util.stderr(f'Completed processing in {elapsed_time_ms}ms. Used {api.requests} API calls, with {api.failures} of those failing. Failure rate: {api.failure_rate}%')
#     sys.exit(0)
