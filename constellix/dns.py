"""Manage host records"""

import json
import constellix
import ipaddress
import logging

import util

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class DomainRecordsError(Error):
    """Exception raised for errors adding records to a domain.

    Attributes:
        record -- the domain record
        message -- explanation of the error
    """

    def __init__(self, record, message):
        self.record = record
        self.message = message

class ReadOnlyAttribbuteError(Error):
    """Exception raised when setting a read only attribute

    Attributes:
        attribute (str): The attribute
        message (str): Explanation of the error
    """

    def __init__(self, attribute, message):
        super().__init__()
        self.attribute = attribute
        self.message = message

class DomainUpdateError(Error):
    """Exception raised when updating a domain with no parent id

    Attributes:
        message (str): Explanation of the error
    """

    def __init__(self, message):
        super().__init__()
        self.message = message

class Domain(object):
    """Reference to a domain"""

    def __init__(self, fqdn=None, verbosity=0, ttl = None):
        super().__init__()
        self.__api = constellix.api(verbosity=verbosity)
        self.__verbosity = verbosity
        self.__changes = []
        if ttl:
            self.default_ttl = ttl
        else:
            self.deafult_ttl = 3600

        if fqdn:
            domainparts = fqdn.split('.')
            partcount = len(domainparts)

            attempt = 1
            while attempt < partcount+1:
                searchdomainparts = []
                for x in range(attempt, partcount+1, 1):
                    searchdomainparts.append(domainparts[x-1])

                domainData = self.__api.search(".".join(searchdomainparts))

                if domainData:
                    break
                attempt += 1
            
            self.records = Records()
            if domainparts[-1:][0] != "arpa":
                self.ptr = Domain_PTR()
            if domainData and domainData[0]:
                self.parent_id = domainData[0]["id"]
                self.parent_name = domainData[0]["name"]
                self.__parent_record = self.__api.get(self.parent_id)
                if attempt > 1:
                    domain_length = 0-(len(self.parent_name)+1)
                    self.name = fqdn[:domain_length]
                else:
                    self.name = ""

    def __str__(self):
        data = {}
        for attr, value in self.__dict__.items():
            if not attr.startswith('_Domain__'): data[attr] = str(value)
        return str(data)

    @property
    def pending_changes(self):
        if self.__changes and len(self.__changes) > 0:
            return True
        return False
    
    @pending_changes.setter
    def pending_changes(self, pending_changes):
        raise ReadOnlyAttribbuteError("pending_changes", "Can not set pending_changes - it is read only.")

    @property
    def deafult_ttl(self):
        if self.__default_ttl:
            return self.__default_ttl
        return 3600

    @deafult_ttl.setter
    def deafult_ttl(self, deafult_ttl):
        deafult_ttl = int(deafult_ttl)
        if deafult_ttl < 0:
            self.__default_ttl = 0
        elif deafult_ttl >= 604800:
            self.__default_ttl = 604800
        else:
            self.__default_ttl = deafult_ttl

    @property
    def verbosity(self):
        return self.__verbosity

    @verbosity.setter
    def verbosity(self, verbosity):
        verbosity = int(verbosity)
        if verbosity < 0:
            self.__verbosity = 0
        elif verbosity >= 4:
            self.__verbosity = 4
        else:
            self.__verbosity = verbosity

        self.__api.verbosity = self.__verbosity

    def get_all_records(self, record_type = "A"):
        self.records.reset(record_type)
        records = self.__api.search(self.name, self.parent_id, record_type)
        if records and len(records) > 0:
           for record in records:
               data = self.__api.get(self.parent_id,record_type,record["id"])
               if data and "id" in data:
                   setattr(self.records, record_type, Record(provider_data=data))
        return getattr(self.records, record_type)

    def get_known_ptr(self):
        for record_type in ["A", "AAAA"]:
            setattr(self.ptr, record_type, [])
            records = self.get_all_records(record_type)
            if records:
                for record in records:
                    if hasattr(record, "values") and len(record.values) > 0:
                        for ip in record.values:
                            ipaddr = ipaddress.ip_address(ip)
                            arpa = ipaddr.reverse_pointer
                            ptr = Domain(arpa, verbosity=self.verbosity)
                            if ptr and hasattr(ptr, "parent_id"):
                                ptr.get_all_records("PTR")
                                ptr_records = getattr(self.ptr, record_type)
                                ptr_records.append({str(ipaddr):ptr})
        return self.ptr

    def sync_ptr(self):
        if not hasattr(self, "ptr"):
            raise DomainRecordsError("PTR", "No PTR records exist. Try get_known_ptr first.")
        for record_type in ["A", "AAAA"]:
            try:
                records = getattr(self.ptr, record_type)
            except AttributeError: 
                continue
            for record in records:
                for ip in record:
                    ptr = record[ip]
                    logging.info(ptr)

    def __diff(self, record_type, new_values = None):
        current = getattr(self.records, record_type)
        print(self)
        print(current.values)
        if not current and not new_values:
            logging.info("No diff needed both existing and new values are empty.")
            return None
        data = {
            "to_delete": [],
            "to_create": [],
            "exists": []
        }
        for value in new_values:
            logging.info("Checking: %s against %s", value, str(current.values))
            if hasattr(current, "values") and current.values and value in current.values:
                data['exists'].append(value)
            else:
                data['to_create'].append(value)
        if hasattr(current, "values") and current.values:
            for value in current.values:
                logging.info("Checking already existing: %s against %s", value, str(new_values))
                if new_values and not value in new_values:
                    data['to_delete'].append(value)
        return data


    def add_update(self, record_type, values = None):
        if values and isinstance(values, str):
            values = [values]
        diff = self.__diff(record_type, values)
        template = getattr(self, f'template_{record_type}')
        if "to_create" in diff and diff["to_create"]:
            self.__changes.append({
                "type": record_type.lower(),
                "add": True,
                "set": template(diff["to_create"])
            })
        return diff

    def sync(self):
        if not self.__changes:
            logging.info("There are no changes to sync.")
        if not self.parent_id:
            raise DomainUpdateError("There is no parent id for this domain. Can not sync.")
        logging.info("Sending changes.")
        changes = self.__api.bulk(self.parent_id, self.__changes)
        logging.info(changes)
        return self

    def template_A(self, values = None, ttl = None):
        """Template A record

        Attributes:
            values (list): The list of values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }

        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": str(ipaddress.ip_address(value)),
                    "disableFlag": False
                })
        return template

    def template_AAAA(self, values = None, ttl = None):
        """Template AAAA record

        Attributes:
            values (list): The list of AAAA record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": str(ipaddress.ip_address(value)),
                    "disableFlag": False
                })
        return template

    def template_AFSDB(self, values = None, ttl = None):
        """Template AFSDB record

        Attributes:
            values (list): The list of AFSDB record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_APL(self, values = None, ttl = None):
        """Template APL record

        Attributes:
            values (list): The list of APL record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_CAA(self, values = None, ttl = None):
        """Template CAA record

        Attributes:
            values (list): The list of CAA record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_CDNSKEY(self, values = None, ttl = None):
        """Template CDNSKEY record

        Attributes:
            values (list): The list of CDNSKEY record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_CDS(self, values = None, ttl = None):
        """Template CDS record

        Attributes:
            values (list): The list of CDS record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_CERT(self, values = None, ttl = None):
        """Template CERT record

        Attributes:
            values (list): The list of CERT record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_CNAME(self, values = None, ttl = None):
        """Template CNAME record

        Attributes:
            values (list): The list of CNAME record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_CSYNC(self, values = None, ttl = None):
        """Template CSYNC record

        Attributes:
            values (list): The list of CSYNC record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_DHCID(self, values = None, ttl = None):
        """Template DHCID record

        Attributes:
            values (list): The list of DHCID record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_DLV(self, values = None, ttl = None):
        """Template DLV record

        Attributes:
            values (list): The list of DLV record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_DNAME(self, values = None, ttl = None):
        """Template DNAME record

        Attributes:
            values (list): The list of DNAME record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_DNSKEY(self, values = None, ttl = None):
        """Template DNSKEY record

        Attributes:
            values (list): The list of DNSKEY record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_DS(self, values = None, ttl = None):
        """Template DS record

        Attributes:
            values (list): The list of DS record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_EUI(self, values = None, ttl = None):
        """Template EUI record

        Attributes:
            values (list): The list of EUI record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_HINFO(self, values = None, ttl = None):
        """Template HINFO record

        Attributes:
            values (list): The list of HINFO record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_HIP(self, values = None, ttl = None):
        """Template HIP record

        Attributes:
            values (list): The list of HIP record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_IPSECKEY(self, values = None, ttl = None):
        """Template IPSECKEY record

        Attributes:
            values (list): The list of IPSECKEY record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_KEY(self, values = None, ttl = None):
        """Template KEY record

        Attributes:
            values (list): The list of KEY record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_KX(self, values = None, ttl = None):
        """Template KX record

        Attributes:
            values (list): The list of KX record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_LOC(self, values = None, ttl = None):
        """Template LOC record

        Attributes:
            values (list): The list of LOC record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_MX(self, values = None, ttl = None):
        """Template MX record

        Attributes:
            values (list): The list of MX record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_NAPTR(self, values = None, ttl = None):
        """Template NAPTR record

        Attributes:
            values (list): The list of NAPTR record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_NS(self, values = None, ttl = None):
        """Template NS record

        Attributes:
            values (list): The list of NS record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_NSEC(self, values = None, ttl = None):
        """Template NSEC record

        Attributes:
            values (list): The list of NSEC record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_OPENPGPKEY(self, values = None, ttl = None):
        """Template OPENPGPKEY record

        Attributes:
            values (list): The list of OPENPGPKEY record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_PTR(self, values = None, ttl = None):
        """Template PTR record

        Attributes:
            values (list): The list of PTR record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_RRSIG(self, values = None, ttl = None):
        """Template RRSIG record

        Attributes:
            values (list): The list of RRSIG record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_RP(self, values = None, ttl = None):
        """Template RP record

        Attributes:
            values (list): The list of RP record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_SIG(self, values = None, ttl = None):
        """Template SIG record

        Attributes:
            values (list): The list of SIG record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_SMIMEA(self, values = None, ttl = None):
        """Template SMIMEA record

        Attributes:
            values (list): The list of SMIMEA record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_SOA(self, values = None, ttl = None):
        """Template SOA record

        Attributes:
            values (list): The list of SOA record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_SRV(self, values = None, ttl = None):
        """Template SRV record

        Attributes:
            values (list): The list of SRV record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_SSHFP(self, values = None, ttl = None):
        """Template SSHFP record

        Attributes:
            values (list): The list of SSHFP record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_TA(self, values = None, ttl = None):
        """Template TA record

        Attributes:
            values (list): The list of TA record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_TKEY(self, values = None, ttl = None):
        """Template TKEY record

        Attributes:
            values (list): The list of TKEY record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_TLSA(self, values = None, ttl = None):
        """Template TLSA record

        Attributes:
            values (list): The list of TLSA record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_TSIG(self, values = None, ttl = None):
        """Template TSIG record

        Attributes:
            values (list): The list of TSIG record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_TXT(self, values = None, ttl = None):
        """Template TXT record

        Attributes:
            values (list): The list of TXT record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_URI(self, values = None, ttl = None):
        """Template URI record

        Attributes:
            values (list): The list of URI record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

    def template_ZONEMD(self, values = None, ttl = None):
        """Template ZONEMD record

        Attributes:
            values (list): The list of ZONEMD record values to insert into the template
        """
        if not ttl: ttl = self.__default_ttl

        template = {
            "name": self.name,
            "ttl": ttl,
            "roundRobin": []
        }
        if values:
            for value in values:
                template["roundRobin"].append({
                    "value": value,
                    "disableFlag": False
                })
        return template

class Domain_PTR(object):
    """Domain PTR Records"""

    def __init__(self):
        super().__init__()
        self.A = []
        self.AAAA = []

    def __str__(self):
        return str(self.__dict__)

class Record(object):
    """A single domain record"""

    def __init__(self, id = None, record_type = None, name = None, values = None, provider_data = None):
        super().__init__()
        if provider_data:
            self.__provider_data = provider_data
            if "id" in self.__provider_data:
                self.id = self.__provider_data["id"]
            if "name" in self.__provider_data:
                self.name = self.__provider_data["name"].lower()
            if "type" in self.__provider_data:
                self.record_type = self.__provider_data["type"].upper()
            if "value" in self.__provider_data:
                self.values = self.__clean_values(self.__provider_data["value"])
        if id:
            self.id = id
        if record_type:
            self.record_type = record_type
        if name:
            self.name = name
        if values:
            if isinstance(values, str):
                self.values = self.__clean_values([values])
            else:
                self.values = self.__clean_values(values)

    def __clean_values(self,values):
        clean = []
        for value in values:

            if "value" in value and "disableFlag" in value:
                if value["disableFlag"]:
                    continue
                value = value["value"]

            if hasattr(self, "record_type") and (self.record_type == "A" or self.record_type == "AAAA"):
                value = ipaddress.ip_address(value)
            clean.append(str(value))
        return clean

    def __iter__(self):
        for attr, value in self.__dict__.items():
            yield attr, value

    def __str__(self):
        return str(self.__dict__)


class RecordHolder(object):
    """Record Holder"""

    def __init__(self):
        super().__init__()

    def __str__(self):
        data = {}
        for name in self.__dict__:
            data[name] = str(getattr(self, name))
        return str(data)

class Records(object):
    """Domain records"""

    def __init__(self):
        super().__init__()
        self.__record_types = [
            'A',
            'AAAA',
            'AFSDB',
            'APL',
            'CAA',
            'CDNSKEY',
            'CDS',
            'CERT',
            'CNAME',
            'CSYNC',
            'DHCID',
            'DLV',
            'DNAME',
            'DNSKEY',
            'DS',
            'EUI',
            'HINFO',
            'HIP',
            'IPSECKEY',
            'KEY',
            'KX',
            'LOC',
            'MX',
            'NAPTR',
            'NS',
            'NSEC',
            'OPENPGPKEY',
            'PTR',
            'RRSIG',
            'RP',
            'SIG',
            'SMIMEA',
            'SOA',
            'SRV',
            'SSHFP',
            'TA',
            'TKEY',
            'TLSA',
            'TSIG',
            'TXT',
            'URI',
            'ZONEMD'
        ]
    
    @property
    def A(self):
        data = []
        try:
            items = self.__A.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @A.setter
    def A(self, A):
        if isinstance(A, Record):
            if not hasattr(self, "__A"):
                logging.debug("Creating record holder for A")
                self.__A = RecordHolder()
            if not hasattr(A, "name"):
                raise DomainRecordsError(A,'The A domain record has no name')
            logging.debug("Storing %s in A", A.name)
            setattr(self.__A,A.name,A)
        else:
            raise DomainRecordsError(A,'The A domain record must be of Record class')

    @property
    def AAAA(self):
        data = []
        try:
            items = self.__AAAA.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @AAAA.setter
    def AAAA(self, AAAA):
        if isinstance(AAAA, Record):
            if not hasattr(self, "__AAAA"):
                logging.debug("Creating record holder for AAAA")
                self.__AAAA = RecordHolder()
            if not hasattr(AAAA, "name"):
                raise DomainRecordsError(AAAA,'The AAAA domain record has no name')
            logging.debug("Storing %s in AAAA", AAAA.name)
            setattr(self.__AAAA,AAAA.name,AAAA)
        else:
            raise DomainRecordsError(AAAA,'The AAAA domain record must be of Record class')

    @property
    def AFSDB(self):
        data = []
        try:
            items = self.__AFSDB.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @AFSDB.setter
    def AFSDB(self, AFSDB):
        if isinstance(AFSDB, Record):
            if not hasattr(self, "__AFSDB"):
                logging.debug("Creating record holder for AFSDB")
                self.__AFSDB = RecordHolder()
            if not hasattr(AFSDB, "name"):
                raise DomainRecordsError(AFSDB,'The AFSDB domain record has no name')
            logging.debug("Storing %s in AFSDB", AFSDB.name)
            setattr(self.__AFSDB,AFSDB.name,AFSDB)
        else:
            raise DomainRecordsError(AFSDB,'The AFSDB domain record must be of Record class')

    @property
    def APL(self):
        data = []
        try:
            items = self.__APL.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @APL.setter
    def APL(self, APL):
        if isinstance(APL, Record):
            if not hasattr(self, "__APL"):
                logging.debug("Creating record holder for APL")
                self.__APL = RecordHolder()
            if not hasattr(APL, "name"):
                raise DomainRecordsError(APL,'The APL domain record has no name')
            logging.debug("Storing %s in APL", APL.name)
            setattr(self.__APL,APL.name,APL)
        else:
            raise DomainRecordsError(APL,'The APL domain record must be of Record class')

    @property
    def CAA(self):
        data = []
        try:
            items = self.__CAA.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @CAA.setter
    def CAA(self, CAA):
        if isinstance(CAA, Record):
            if not hasattr(self, "__CAA"):
                logging.debug("Creating record holder for CAA")
                self.__CAA = RecordHolder()
            if not hasattr(CAA, "name"):
                raise DomainRecordsError(CAA,'The CAA domain record has no name')
            logging.debug("Storing %s in CAA", CAA.name)
            setattr(self.__CAA,CAA.name,CAA)
        else:
            raise DomainRecordsError(CAA,'The CAA domain record must be of Record class')

    @property
    def CDNSKEY(self):
        data = []
        try:
            items = self.__CDNSKEY.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @CDNSKEY.setter
    def CDNSKEY(self, CDNSKEY):
        if isinstance(CDNSKEY, Record):
            if not hasattr(self, "__CDNSKEY"):
                logging.debug("Creating record holder for CDNSKEY")
                self.__CDNSKEY = RecordHolder()
            if not hasattr(CDNSKEY, "name"):
                raise DomainRecordsError(CDNSKEY,'The CDNSKEY domain record has no name')
            logging.debug("Storing %s in CDNSKEY", CDNSKEY.name)
            setattr(self.__CDNSKEY,CDNSKEY.name,CDNSKEY)
        else:
            raise DomainRecordsError(CDNSKEY,'The CDNSKEY domain record must be of Record class')

    @property
    def CDS(self):
        data = []
        try:
            items = self.__CDS.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @CDS.setter
    def CDS(self, CDS):
        if isinstance(CDS, Record):
            if not hasattr(self, "__CDS"):
                logging.debug("Creating record holder for CDS")
                self.__CDS = RecordHolder()
            if not hasattr(CDS, "name"):
                raise DomainRecordsError(CDS,'The CDS domain record has no name')
            logging.debug("Storing %s in CDS", CDS.name)
            setattr(self.__CDS,CDS.name,CDS)
        else:
            raise DomainRecordsError(CDS,'The CDS domain record must be of Record class')

    @property
    def CERT(self):
        data = []
        try:
            items = self.__CERT.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @CERT.setter
    def CERT(self, CERT):
        if isinstance(CERT, Record):
            if not hasattr(self, "__CERT"):
                logging.debug("Creating record holder for CERT")
                self.__CERT = RecordHolder()
            if not hasattr(CERT, "name"):
                raise DomainRecordsError(CERT,'The CERT domain record has no name')
            logging.debug("Storing %s in CERT", CERT.name)
            setattr(self.__CERT,CERT.name,CERT)
        else:
            raise DomainRecordsError(CERT,'The CERT domain record must be of Record class')

    @property
    def CNAME(self):
        data = []
        try:
            items = self.__CNAME.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @CNAME.setter
    def CNAME(self, CNAME):
        if isinstance(CNAME, Record):
            if not hasattr(self, "__CNAME"):
                logging.debug("Creating record holder for CNAME")
                self.__CNAME = RecordHolder()
            if not hasattr(CNAME, "name"):
                raise DomainRecordsError(CNAME,'The CNAME domain record has no name')
            logging.debug("Storing %s in CNAME", CNAME.name)
            setattr(self.__CNAME,CNAME.name,CNAME)
        else:
            raise DomainRecordsError(CNAME,'The CNAME domain record must be of Record class')

    @property
    def CSYNC(self):
        data = []
        try:
            items = self.__CSYNC.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @CSYNC.setter
    def CSYNC(self, CSYNC):
        if isinstance(CSYNC, Record):
            if not hasattr(self, "__CSYNC"):
                logging.debug("Creating record holder for CSYNC")
                self.__CSYNC = RecordHolder()
            if not hasattr(CSYNC, "name"):
                raise DomainRecordsError(CSYNC,'The CSYNC domain record has no name')
            logging.debug("Storing %s in CSYNC", CSYNC.name)
            setattr(self.__CSYNC,CSYNC.name,CSYNC)
        else:
            raise DomainRecordsError(CSYNC,'The CSYNC domain record must be of Record class')

    @property
    def DHCID(self):
        data = []
        try:
            items = self.__DHCID.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @DHCID.setter
    def DHCID(self, DHCID):
        if isinstance(DHCID, Record):
            if not hasattr(self, "__DHCID"):
                logging.debug("Creating record holder for DHCID")
                self.__DHCID = RecordHolder()
            if not hasattr(DHCID, "name"):
                raise DomainRecordsError(DHCID,'The DHCID domain record has no name')
            logging.debug("Storing %s in DHCID", DHCID.name)
            setattr(self.__DHCID,DHCID.name,DHCID)
        else:
            raise DomainRecordsError(DHCID,'The DHCID domain record must be of Record class')

    @property
    def DLV(self):
        data = []
        try:
            items = self.__DLV.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @DLV.setter
    def DLV(self, DLV):
        if isinstance(DLV, Record):
            if not hasattr(self, "__DLV"):
                logging.debug("Creating record holder for DLV")
                self.__DLV = RecordHolder()
            if not hasattr(DLV, "name"):
                raise DomainRecordsError(DLV,'The DLV domain record has no name')
            logging.debug("Storing %s in DLV", DLV.name)
            setattr(self.__DLV,DLV.name,DLV)
        else:
            raise DomainRecordsError(DLV,'The DLV domain record must be of Record class')

    @property
    def DNAME(self):
        data = []
        try:
            items = self.__DNAME.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @DNAME.setter
    def DNAME(self, DNAME):
        if isinstance(DNAME, Record):
            if not hasattr(self, "__DNAME"):
                logging.debug("Creating record holder for DNAME")
                self.__DNAME = RecordHolder()
            if not hasattr(DNAME, "name"):
                raise DomainRecordsError(DNAME,'The DNAME domain record has no name')
            logging.debug("Storing %s in DNAME", DNAME.name)
            setattr(self.__DNAME,DNAME.name,DNAME)
        else:
            raise DomainRecordsError(DNAME,'The DNAME domain record must be of Record class')

    @property
    def DNSKEY(self):
        data = []
        try:
            items = self.__DNSKEY.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @DNSKEY.setter
    def DNSKEY(self, DNSKEY):
        if isinstance(DNSKEY, Record):
            if not hasattr(self, "__DNSKEY"):
                logging.debug("Creating record holder for DNSKEY")
                self.__DNSKEY = RecordHolder()
            if not hasattr(DNSKEY, "name"):
                raise DomainRecordsError(DNSKEY,'The DNSKEY domain record has no name')
            logging.debug("Storing %s in DNSKEY", DNSKEY.name)
            setattr(self.__DNSKEY,DNSKEY.name,DNSKEY)
        else:
            raise DomainRecordsError(DNSKEY,'The DNSKEY domain record must be of Record class')

    @property
    def DS(self):
        data = []
        try:
            items = self.__DS.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @DS.setter
    def DS(self, DS):
        if isinstance(DS, Record):
            if not hasattr(self, "__DS"):
                logging.debug("Creating record holder for DS")
                self.__DS = RecordHolder()
            if not hasattr(DS, "name"):
                raise DomainRecordsError(DS,'The DS domain record has no name')
            logging.debug("Storing %s in DS", DS.name)
            setattr(self.__DS,DS.name,DS)
        else:
            raise DomainRecordsError(DS,'The DS domain record must be of Record class')

    @property
    def EUI(self):
        data = []
        try:
            items = self.__EUI.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @EUI.setter
    def EUI(self, EUI):
        if isinstance(EUI, Record):
            if not hasattr(self, "__EUI"):
                logging.debug("Creating record holder for EUI")
                self.__EUI = RecordHolder()
            if not hasattr(EUI, "name"):
                raise DomainRecordsError(EUI,'The EUI domain record has no name')
            logging.debug("Storing %s in EUI", EUI.name)
            setattr(self.__EUI,EUI.name,EUI)
        else:
            raise DomainRecordsError(EUI,'The EUI domain record must be of Record class')

    @property
    def HINFO(self):
        data = []
        try:
            items = self.__HINFO.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @HINFO.setter
    def HINFO(self, HINFO):
        if isinstance(HINFO, Record):
            if not hasattr(self, "__HINFO"):
                logging.debug("Creating record holder for HINFO")
                self.__HINFO = RecordHolder()
            if not hasattr(HINFO, "name"):
                raise DomainRecordsError(HINFO,'The HINFO domain record has no name')
            logging.debug("Storing %s in HINFO", HINFO.name)
            setattr(self.__HINFO,HINFO.name,HINFO)
        else:
            raise DomainRecordsError(HINFO,'The HINFO domain record must be of Record class')

    @property
    def HIP(self):
        data = []
        try:
            items = self.__HIP.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @HIP.setter
    def HIP(self, HIP):
        if isinstance(HIP, Record):
            if not hasattr(self, "__HIP"):
                logging.debug("Creating record holder for HIP")
                self.__HIP = RecordHolder()
            if not hasattr(HIP, "name"):
                raise DomainRecordsError(HIP,'The HIP domain record has no name')
            logging.debug("Storing %s in HIP", HIP.name)
            setattr(self.__HIP,HIP.name,HIP)
        else:
            raise DomainRecordsError(HIP,'The HIP domain record must be of Record class')

    @property
    def IPSECKEY(self):
        data = []
        try:
            items = self.__IPSECKEY.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @IPSECKEY.setter
    def IPSECKEY(self, IPSECKEY):
        if isinstance(IPSECKEY, Record):
            if not hasattr(self, "__IPSECKEY"):
                logging.debug("Creating record holder for IPSECKEY")
                self.__IPSECKEY = RecordHolder()
            if not hasattr(IPSECKEY, "name"):
                raise DomainRecordsError(IPSECKEY,'The IPSECKEY domain record has no name')
            logging.debug("Storing %s in IPSECKEY", IPSECKEY.name)
            setattr(self.__IPSECKEY,IPSECKEY.name,IPSECKEY)
        else:
            raise DomainRecordsError(IPSECKEY,'The IPSECKEY domain record must be of Record class')

    @property
    def KEY(self):
        data = []
        try:
            items = self.__KEY.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @KEY.setter
    def KEY(self, KEY):
        if isinstance(KEY, Record):
            if not hasattr(self, "__KEY"):
                logging.debug("Creating record holder for KEY")
                self.__KEY = RecordHolder()
            if not hasattr(KEY, "name"):
                raise DomainRecordsError(KEY,'The KEY domain record has no name')
            logging.debug("Storing %s in KEY", KEY.name)
            setattr(self.__KEY,KEY.name,KEY)
        else:
            raise DomainRecordsError(KEY,'The KEY domain record must be of Record class')

    @property
    def KX(self):
        data = []
        try:
            items = self.__KX.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @KX.setter
    def KX(self, KX):
        if isinstance(KX, Record):
            if not hasattr(self, "__KX"):
                logging.debug("Creating record holder for KX")
                self.__KX = RecordHolder()
            if not hasattr(KX, "name"):
                raise DomainRecordsError(KX,'The KX domain record has no name')
            logging.debug("Storing %s in KX", KX.name)
            setattr(self.__KX,KX.name,KX)
        else:
            raise DomainRecordsError(KX,'The KX domain record must be of Record class')

    @property
    def LOC(self):
        data = []
        try:
            items = self.__LOC.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @LOC.setter
    def LOC(self, LOC):
        if isinstance(LOC, Record):
            if not hasattr(self, "__LOC"):
                logging.debug("Creating record holder for LOC")
                self.__LOC = RecordHolder()
            if not hasattr(LOC, "name"):
                raise DomainRecordsError(LOC,'The LOC domain record has no name')
            logging.debug("Storing %s in LOC", LOC.name)
            setattr(self.__LOC,LOC.name,LOC)
        else:
            raise DomainRecordsError(LOC,'The LOC domain record must be of Record class')

    @property
    def MX(self):
        data = []
        try:
            items = self.__MX.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @MX.setter
    def MX(self, MX):
        if isinstance(MX, Record):
            if not hasattr(self, "__MX"):
                logging.debug("Creating record holder for MX")
                self.__MX = RecordHolder()
            if not hasattr(MX, "name"):
                raise DomainRecordsError(MX,'The MX domain record has no name')
            logging.debug("Storing %s in MX", MX.name)
            setattr(self.__MX,MX.name,MX)
        else:
            raise DomainRecordsError(MX,'The MX domain record must be of Record class')

    @property
    def NAPTR(self):
        data = []
        try:
            items = self.__NAPTR.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @NAPTR.setter
    def NAPTR(self, NAPTR):
        if isinstance(NAPTR, Record):
            if not hasattr(self, "__NAPTR"):
                logging.debug("Creating record holder for NAPTR")
                self.__NAPTR = RecordHolder()
            if not hasattr(NAPTR, "name"):
                raise DomainRecordsError(NAPTR,'The NAPTR domain record has no name')
            logging.debug("Storing %s in NAPTR", NAPTR.name)
            setattr(self.__NAPTR,NAPTR.name,NAPTR)
        else:
            raise DomainRecordsError(NAPTR,'The NAPTR domain record must be of Record class')

    @property
    def NS(self):
        data = []
        try:
            items = self.__NS.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @NS.setter
    def NS(self, NS):
        if isinstance(NS, Record):
            if not hasattr(self, "__NS"):
                logging.debug("Creating record holder for NS")
                self.__NS = RecordHolder()
            if not hasattr(NS, "name"):
                raise DomainRecordsError(NS,'The NS domain record has no name')
            logging.debug("Storing %s in NS", NS.name)
            setattr(self.__NS,NS.name,NS)
        else:
            raise DomainRecordsError(NS,'The NS domain record must be of Record class')

    @property
    def NSEC(self):
        data = []
        try:
            items = self.__NSEC.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @NSEC.setter
    def NSEC(self, NSEC):
        if isinstance(NSEC, Record):
            if not hasattr(self, "__NSEC"):
                logging.debug("Creating record holder for NSEC")
                self.__NSEC = RecordHolder()
            if not hasattr(NSEC, "name"):
                raise DomainRecordsError(NSEC,'The NSEC domain record has no name')
            logging.debug("Storing %s in NSEC", NSEC.name)
            setattr(self.__NSEC,NSEC.name,NSEC)
        else:
            raise DomainRecordsError(NSEC,'The NSEC domain record must be of Record class')

    @property
    def OPENPGPKEY(self):
        data = []
        try:
            items = self.__OPENPGPKEY.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @OPENPGPKEY.setter
    def OPENPGPKEY(self, OPENPGPKEY):
        if isinstance(OPENPGPKEY, Record):
            if not hasattr(self, "__OPENPGPKEY"):
                logging.debug("Creating record holder for OPENPGPKEY")
                self.__OPENPGPKEY = RecordHolder()
            if not hasattr(OPENPGPKEY, "name"):
                raise DomainRecordsError(OPENPGPKEY,'The OPENPGPKEY domain record has no name')
            logging.debug("Storing %s in OPENPGPKEY", OPENPGPKEY.name)
            setattr(self.__OPENPGPKEY,OPENPGPKEY.name,OPENPGPKEY)
        else:
            raise DomainRecordsError(OPENPGPKEY,'The OPENPGPKEY domain record must be of Record class')

    @property
    def PTR(self):
        data = []
        try:
            items = self.__PTR.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @PTR.setter
    def PTR(self, PTR):
        if isinstance(PTR, Record):
            if not hasattr(self, "__PTR"):
                logging.debug("Creating record holder for PTR")
                self.__PTR = RecordHolder()
            if not hasattr(PTR, "name"):
                raise DomainRecordsError(PTR,'The PTR domain record has no name')
            logging.debug("Storing %s in PTR", PTR.name)
            setattr(self.__PTR,PTR.name,PTR)
        else:
            raise DomainRecordsError(PTR,'The PTR domain record must be of Record class')

    @property
    def RRSIG(self):
        data = []
        try:
            items = self.__RRSIG.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @RRSIG.setter
    def RRSIG(self, RRSIG):
        if isinstance(RRSIG, Record):
            if not hasattr(self, "__RRSIG"):
                logging.debug("Creating record holder for RRSIG")
                self.__RRSIG = RecordHolder()
            if not hasattr(RRSIG, "name"):
                raise DomainRecordsError(RRSIG,'The RRSIG domain record has no name')
            logging.debug("Storing %s in RRSIG", RRSIG.name)
            setattr(self.__RRSIG,RRSIG.name,RRSIG)
        else:
            raise DomainRecordsError(RRSIG,'The RRSIG domain record must be of Record class')

    @property
    def RP(self):
        data = []
        try:
            items = self.__RP.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @RP.setter
    def RP(self, RP):
        if isinstance(RP, Record):
            if not hasattr(self, "__RP"):
                logging.debug("Creating record holder for RP")
                self.__RP = RecordHolder()
            if not hasattr(RP, "name"):
                raise DomainRecordsError(RP,'The RP domain record has no name')
            logging.debug("Storing %s in RP", RP.name)
            setattr(self.__RP,RP.name,RP)
        else:
            raise DomainRecordsError(RP,'The RP domain record must be of Record class')

    @property
    def SIG(self):
        data = []
        try:
            items = self.__SIG.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @SIG.setter
    def SIG(self, SIG):
        if isinstance(SIG, Record):
            if not hasattr(self, "__SIG"):
                logging.debug("Creating record holder for SIG")
                self.__SIG = RecordHolder()
            if not hasattr(SIG, "name"):
                raise DomainRecordsError(SIG,'The SIG domain record has no name')
            logging.debug("Storing %s in SIG", SIG.name)
            setattr(self.__SIG,SIG.name,SIG)
        else:
            raise DomainRecordsError(SIG,'The SIG domain record must be of Record class')

    @property
    def SMIMEA(self):
        data = []
        try:
            items = self.__SMIMEA.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @SMIMEA.setter
    def SMIMEA(self, SMIMEA):
        if isinstance(SMIMEA, Record):
            if not hasattr(self, "__SMIMEA"):
                logging.debug("Creating record holder for SMIMEA")
                self.__SMIMEA = RecordHolder()
            if not hasattr(SMIMEA, "name"):
                raise DomainRecordsError(SMIMEA,'The SMIMEA domain record has no name')
            logging.debug("Storing %s in SMIMEA", SMIMEA.name)
            setattr(self.__SMIMEA,SMIMEA.name,SMIMEA)
        else:
            raise DomainRecordsError(SMIMEA,'The SMIMEA domain record must be of Record class')

    @property
    def SOA(self):
        data = []
        try:
            items = self.__SOA.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @SOA.setter
    def SOA(self, SOA):
        if isinstance(SOA, Record):
            if not hasattr(self, "__SOA"):
                logging.debug("Creating record holder for SOA")
                self.__SOA = RecordHolder()
            if not hasattr(SOA, "name"):
                raise DomainRecordsError(SOA,'The SOA domain record has no name')
            logging.debug("Storing %s in SOA", SOA.name)
            setattr(self.__SOA,SOA.name,SOA)
        else:
            raise DomainRecordsError(SOA,'The SOA domain record must be of Record class')

    @property
    def SRV(self):
        data = []
        try:
            items = self.__SRV.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @SRV.setter
    def SRV(self, SRV):
        if isinstance(SRV, Record):
            if not hasattr(self, "__SRV"):
                logging.debug("Creating record holder for SRV")
                self.__SRV = RecordHolder()
            if not hasattr(SRV, "name"):
                raise DomainRecordsError(SRV,'The SRV domain record has no name')
            logging.debug("Storing %s in SRV", SRV.name)
            setattr(self.__SRV,SRV.name,SRV)
        else:
            raise DomainRecordsError(SRV,'The SRV domain record must be of Record class')

    @property
    def SSHFP(self):
        data = []
        try:
            items = self.__SSHFP.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @SSHFP.setter
    def SSHFP(self, SSHFP):
        if isinstance(SSHFP, Record):
            if not hasattr(self, "__SSHFP"):
                logging.debug("Creating record holder for SSHFP")
                self.__SSHFP = RecordHolder()
            if not hasattr(SSHFP, "name"):
                raise DomainRecordsError(SSHFP,'The SSHFP domain record has no name')
            logging.debug("Storing %s in SSHFP", SSHFP.name)
            setattr(self.__SSHFP,SSHFP.name,SSHFP)
        else:
            raise DomainRecordsError(SSHFP,'The SSHFP domain record must be of Record class')

    @property
    def TA(self):
        data = []
        try:
            items = self.__TA.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @TA.setter
    def TA(self, TA):
        if isinstance(TA, Record):
            if not hasattr(self, "__TA"):
                logging.debug("Creating record holder for TA")
                self.__TA = RecordHolder()
            if not hasattr(TA, "name"):
                raise DomainRecordsError(TA,'The TA domain record has no name')
            logging.debug("Storing %s in TA", TA.name)
            setattr(self.__TA,TA.name,TA)
        else:
            raise DomainRecordsError(TA,'The TA domain record must be of Record class')

    @property
    def TKEY(self):
        data = []
        try:
            items = self.__TKEY.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @TKEY.setter
    def TKEY(self, TKEY):
        if isinstance(TKEY, Record):
            if not hasattr(self, "__TKEY"):
                logging.debug("Creating record holder for TKEY")
                self.__TKEY = RecordHolder()
            if not hasattr(TKEY, "name"):
                raise DomainRecordsError(TKEY,'The TKEY domain record has no name')
            logging.debug("Storing %s in TKEY", TKEY.name)
            setattr(self.__TKEY,TKEY.name,TKEY)
        else:
            raise DomainRecordsError(TKEY,'The TKEY domain record must be of Record class')

    @property
    def TLSA(self):
        data = []
        try:
            items = self.__TLSA.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @TLSA.setter
    def TLSA(self, TLSA):
        if isinstance(TLSA, Record):
            if not hasattr(self, "__TLSA"):
                logging.debug("Creating record holder for TLSA")
                self.__TLSA = RecordHolder()
            if not hasattr(TLSA, "name"):
                raise DomainRecordsError(TLSA,'The TLSA domain record has no name')
            logging.debug("Storing %s in TLSA", TLSA.name)
            setattr(self.__TLSA,TLSA.name,TLSA)
        else:
            raise DomainRecordsError(TLSA,'The TLSA domain record must be of Record class')

    @property
    def TSIG(self):
        data = []
        try:
            items = self.__TSIG.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @TSIG.setter
    def TSIG(self, TSIG):
        if isinstance(TSIG, Record):
            if not hasattr(self, "__TSIG"):
                logging.debug("Creating record holder for TSIG")
                self.__TSIG = RecordHolder()
            if not hasattr(TSIG, "name"):
                raise DomainRecordsError(TSIG,'The TSIG domain record has no name')
            logging.debug("Storing %s in TSIG", TSIG.name)
            setattr(self.__TSIG,TSIG.name,TSIG)
        else:
            raise DomainRecordsError(TSIG,'The TSIG domain record must be of Record class')

    @property
    def TXT(self):
        data = []
        try:
            items = self.__TXT.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @TXT.setter
    def TXT(self, TXT):
        if isinstance(TXT, Record):
            if not hasattr(self, "__TXT"):
                logging.debug("Creating record holder for TXT")
                self.__TXT = RecordHolder()
            if not hasattr(TXT, "name"):
                raise DomainRecordsError(TXT,'The TXT domain record has no name')
            logging.debug("Storing %s in TXT", TXT.name)
            setattr(self.__TXT,TXT.name,TXT)
        else:
            raise DomainRecordsError(TXT,'The TXT domain record must be of Record class')

    @property
    def URI(self):
        data = []
        try:
            items = self.__URI.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @URI.setter
    def URI(self, URI):
        if isinstance(URI, Record):
            if not hasattr(self, "__URI"):
                logging.debug("Creating record holder for URI")
                self.__URI = RecordHolder()
            if not hasattr(URI, "name"):
                raise DomainRecordsError(URI,'The URI domain record has no name')
            logging.debug("Storing %s in URI", URI.name)
            setattr(self.__URI,URI.name,URI)
        else:
            raise DomainRecordsError(URI,'The URI domain record must be of Record class')

    @property
    def ZONEMD(self):
        data = []
        try:
            items = self.__ZONEMD.__dict__.items()
            for name, record in items:
                data.append(record)
        except AttributeError:
            pass
        return data

    @ZONEMD.setter
    def ZONEMD(self, ZONEMD):
        if isinstance(ZONEMD, Record):
            if not hasattr(self, "__ZONEMD"):
                logging.debug("Creating record holder for ZONEMD")
                self.__ZONEMD = RecordHolder()
            if not hasattr(ZONEMD, "name"):
                raise DomainRecordsError(ZONEMD,'The ZONEMD domain record has no name')
            logging.debug("Storing %s in ZONEMD", ZONEMD.name)
            setattr(self.__ZONEMD,ZONEMD.name,ZONEMD)
        else:
            raise DomainRecordsError(ZONEMD,'The ZONEMD domain record must be of Record class')

    def reset(self, record_type = None):
        if not record_type:
            for rt in self.__record_types:
                self.reset(rt)
            return True

        if not record_type in self.__record_types:
            return False

        if hasattr(self, "__" + record_type):
            return delattr(self, "__" + record_type)

        return True

    def __str__(self):
        data = {}
        for record_type in self.__record_types:
            if hasattr(self, f'__{record_type}'):
                data[record_type] = getattr(self, f'__{record_type}')
            else:
                data[record_type] = None
        return str(data)