"""Manage host records"""

import json
import constellix
import ipaddress
import logging
import re

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
        self.__changes = {}
        if ttl:
            self.default_ttl = ttl
        else:
            self.default_ttl = 3600

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
        if self.__changes and len(self.__changes.__dict__.items()) > 0:
            return True
        return False
    
    @pending_changes.setter
    def pending_changes(self, pending_changes):
        raise ReadOnlyAttribbuteError("pending_changes", "Can not set pending_changes - it is read only.")

    @property
    def default_ttl(self):
        if self.__default_ttl:
            return self.__default_ttl
        return 3600

    @default_ttl.setter
    def default_ttl(self, default_ttl):
        default_ttl = int(default_ttl)
        if default_ttl < 0:
            self.__default_ttl = 0
        elif default_ttl >= 604800:
            self.__default_ttl = 604800
        else:
            self.__default_ttl = default_ttl

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
        if not (hasattr(self, "name") and hasattr(self, "parent_id")): return getattr(self.records, record_type)
        records = self.__api.search(self.name, self.parent_id, record_type)
        if records and len(records) > 0:
           for record in records:
               data = self.__api.get(self.parent_id,record_type,record["id"])
               if data and "id" in data:
                   setattr(self.records, record_type, Record(provider_data=data))
        return getattr(self.records, record_type)

    def get_known_ptr(self):
        for record_type in ["A", "AAAA"]:
            setattr(self.ptr, record_type, {})
            record = self.get_all_records(record_type)
            if not record: continue
            if hasattr(record, "values") and len(record.values) > 0:
                for ip in record.values:
                    ipaddr = ipaddress.ip_address(ip)
                    arpa = ipaddr.reverse_pointer
                    ptr = Domain(arpa, verbosity=self.verbosity)
                    if ptr and hasattr(ptr, "parent_id"):
                        ptr.get_all_records("PTR")
                        ptr_records = getattr(self.ptr, record_type)
                        ptr_records[str(ipaddr)] = ptr
        return self.ptr

    def sync_ptr(self):
        if not hasattr(self, "ptr"):
            raise DomainRecordsError("PTR", "No PTR records exist. Try get_known_ptr first.")
        for record_type in ["A", "AAAA"]:
            diff = self.__ptrdiff(record_type)
            if not diff:
                continue
            if "to_create" in diff and diff["to_create"]:
                for record in diff["to_create"]:
                    if not str(record["parent_id"]) in self.__changes: self.__changes[str(record["parent_id"])] = []
                    append = {
                        "type": "ptr",
                        "add": True,
                        "set": {
                            "name": record["name"],
                            "ttl": self.default_ttl,
                            "roundRobin": []
                        }
                    }
                    for value in record["values"]:
                        append["set"]["roundRobin"].append({"value":value})
                    self.__changes[str(record["parent_id"])].append(append)
            if "to_delete" in diff and diff["to_delete"]:
                for record in diff["to_delete"]:
                    if not str(record["parent_id"]) in self.__changes: self.__changes[str(record["parent_id"])] = []
                    for value in record["values"]:
                        delete = {
                            "type": "ptr",
                            "delete": True,
                            "filter":{"field": "id", "op": "eq", "value":value},
                            "set": {}
                        }
                        self.__changes[str(record["parent_id"])].append(delete)
            if "to_update" in diff and diff["to_update"]:
                for record in diff["to_update"]:
                    if not str(record["parent_id"]) in self.__changes: self.__changes[str(record["parent_id"])] = []
                    update = {
                        "type": "ptr",
                        "update": True,
                        "filter":{"field": "id", "op": "eq", "value":record["id"]},
                        "set": {
                            "name": record["name"],
                            "ttl": self.default_ttl,
                            "roundRobin": []
                        }
                    }
                    for value in record["values"]:
                        update["set"]["roundRobin"].append({"value":value})
                    self.__changes[str(record["parent_id"])].append(update)

        return self.__changes

    def __ptrdiff(self, record_type):
        source = None
        current = None
        if self.__changes and str(self.parent_id) in self.__changes:
            for change in self.__changes[str(self.parent_id)]:
                if change["type"].lower() == record_type.lower():
                    values = []
                    if ("update" in change and change["update"]) or ("add" in change and change["add"]):
                        for value in change["set"]["roundRobin"]:
                            if not value["disableFlag"]:
                                values.append(value["value"])
                    source = "Pending domain changes"
                    current = Record(record_type=record_type, values=values)

        if not current:
            source = "Domain record"
            current = getattr(self.records, record_type, None)

        ptr = getattr(self.ptr, record_type, None)
        if not current and not ptr:
            logging.info("No %s diff needed both existing and new values are empty.", record_type)
            return None

        data = {
            "to_delete": [],
            "to_update": [],
            "to_create": [],
            "exists": []
        }

        fqdn = self.parent_name + '.'
        if self.name and len(self.name)>0:
            fqdn = f'{self.name}.{fqdn}'

        if ptr:
            for ip, domain_record in ptr.items():
                if hasattr(domain_record.records.PTR, "id") and not hasattr(current, "values"):
                    data["to_delete"].append({
                        "parent_id": domain_record.parent_id,
                        "values": [domain_record.records.PTR.id]
                    })
                elif hasattr(current, "values") and not ip in current.values and hasattr(domain_record.records.PTR, "id"):
                    data["to_delete"].append({
                        "parent_id": domain_record.parent_id,
                        "values": [domain_record.records.PTR.id]
                    })
                elif hasattr(current, "values") and not ip in current.values and not hasattr(domain_record.records.PTR, "id"):
                    data["to_create"].append({
                        "parent_id": domain_record.parent_id,
                        "name": domain_record.name,
                        "values": [
                            fqdn
                        ]
                    })

        if current and hasattr(current, "values") and current.values:
            for value in current.values:

                ipaddr = ipaddress.ip_address(value)
                arpa = ipaddr.reverse_pointer

                ptr_record = None

                if value in ptr and not hasattr(ptr[value],"id"):
                    ptr_record = ptr[value]
                elif not value in ptr:
                    ptr_record = Domain(arpa, verbosity=self.verbosity)
                    ptr_record.get_all_records("PTR")
                else:
                    data["exists"].append(value)

                if ptr_record and hasattr(ptr_record, "parent_id"):
                    if hasattr(ptr_record.records, "PTR") and ptr_record.records.PTR and hasattr(ptr_record.records.PTR, "id") and ptr_record.records.PTR.id:
                        data["to_update"].append({
                            "parent_id": ptr_record.parent_id,
                            "id": ptr_record.records.PTR.id,
                            "name": ptr_record.name,
                            "values": [
                                fqdn
                            ]
                        })
                    else:
                        data["to_create"].append({
                            "parent_id": ptr_record.parent_id,
                            "name": ptr_record.name,
                            "values": [
                                fqdn
                            ]
                        })
        return data

    def __diff(self, record_type, new_values = None):
        current = getattr(self.records, record_type)
        if not current and not new_values:
            logging.info("No %s diff needed both existing and new values are empty.", record_type)
            return None
        data = {
            "to_delete": [],
            "to_update": [],
            "to_create": [],
            "exists": []
        }

        if not new_values:
            data["to_delete"].append(current.id)
            return data

        prefect_match = True

        for value in new_values:
            if not (hasattr(current, "values") and current.values and value in current.values):
                prefect_match = False
                break

        if hasattr(current, "values") and current.values:
            for value in current.values:
                if not value in new_values:
                    prefect_match = False
                    break
        else:
            prefect_match = False

        if prefect_match:
            data["exists"].append(current.id)
        elif hasattr(current, "id") and current.id:
            data["to_update"].append({
                "id": current.id,
                "values": new_values
            })
        else:
            data["to_create"] = new_values

        return data


    def add_update(self, record_type, values = None):
        if values and isinstance(values, str):
            values = [values]
        diff = self.__diff(record_type, values)
        if not diff:
            return self.__changes
        template = getattr(self, f'template_{record_type}')
        if "to_create" in diff and diff["to_create"]:
            if not str(self.parent_id) in self.__changes: self.__changes[str(self.parent_id)] = []
            self.__changes[str(self.parent_id)].append({
                "type": record_type.lower(),
                "add": True,
                "set": template(diff["to_create"])
            })
        if "to_delete" in diff and diff["to_delete"]:
            for id in diff["to_delete"]:
                if not str(self.parent_id) in self.__changes: self.__changes[str(self.parent_id)] = []
                self.__changes[str(self.parent_id)].append({
                    "type": record_type.lower(),
                    "delete": True,
                    "filter":{"field": "id", "op": "eq", "value":id},
                    "set": {}
                })
        if "to_update" in diff and diff["to_update"]:
            for update in diff["to_update"]:
                if not str(self.parent_id) in self.__changes: self.__changes[str(self.parent_id)] = []
                self.__changes[str(self.parent_id)].append({
                    "type": record_type.lower(),
                    "update": True,
                    "filter":{"field": "id", "op": "eq", "value":update["id"]},
                    "set": template(update["values"])
                })
        return self.__changes

    def sync(self):
        if not self.__changes:
            logging.info("There are no changes to sync.")
            return {
                "added": 0,
                "updated": 0,
                "deleted": 0
            }

        added = 0
        updated = 0
        deleted = 0

        for parent_id, changes in self.__changes.items():
            change_types = {
                "update": 0,
                "create": 0,
                "delete": 0,
            }

            for change in changes:
                if "add" in change:
                    change_types["create"] += 1
                elif "update" in change:
                    change_types["update"] += 1
                elif "delete" in change:
                    change_types["delete"] += 1

            logging.debug("Sending changes for %i: %s",int(parent_id), str(changes))
            result = self.__api.bulk(parent_id, changes)
            if not "success" in result:
                raise DomainUpdateError("Unable to update domain")

            this_added = 0
            this_updated = 0
            this_deleted = 0

            update_search = re.compile(r'(?P<added>\d+) record\(s\) added|(?P<updated>\d+) record\(s\) updated|(?P<deleted>\d+) record\(s\) deleted', re.MULTILINE)
            for l in update_search.finditer(result['success']):
                    if(l.group("added")):
                            this_added = int(l.group("added"))
                    elif(l.group("updated")):
                            this_updated = int(l.group("updated"))
                    elif(l.group("deleted")):
                            this_deleted = int(l.group("deleted"))
            
            if not this_added == change_types['create']:
                raise DomainUpdateError(f'Failed to complete record creation {this_added}/{change_types["create"]}')
            elif not this_updated == change_types['update']:
                raise DomainUpdateError(f'Failed to complete record update {this_updated}/{change_types["update"]}')
            elif not this_deleted == change_types['delete']:
                raise DomainUpdateError(f'Failed to complete record delete {this_deleted}/{change_types["delete"]}')

            added += this_added
            updated += this_updated
            deleted += this_deleted

        return {
            "added": added,
            "updated": updated,
            "deleted": deleted
        }

    def template_A(self, values = None, ttl = None):
        """Template A record

        Attributes:
            values (list): The list of values to insert into the template
        """
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        if not ttl: ttl = self.default_ttl

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
        self.A = {}
        self.AAAA = {}

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
            data = self.__A
        except AttributeError:
            pass
        return data

    @A.setter
    def A(self, A):
        if isinstance(A, Record):
            if hasattr(self, "__A"):
                logging.debug("Overwriting current record for A")
            logging.debug("Storing '%s' in A", A.name)
            self.__A = A
        else:
            raise DomainRecordsError(A,'The A domain record must be of Record class')

    @property
    def AAAA(self):
        data = []
        try:
            data = self.__AAAA
        except AttributeError:
            pass
        return data

    @AAAA.setter
    def AAAA(self, AAAA):
        if isinstance(AAAA, Record):
            if hasattr(self, "__AAAA"):
                logging.debug("Overwriting current record for AAAA")
            logging.debug("Storing '%s' in AAAA", AAAA.name)
            self.__AAAA = AAAA
        else:
            raise DomainRecordsError(AAAA,'The AAAA domain record must be of Record class')

    @property
    def AFSDB(self):
        data = []
        try:
            data = self.__AFSDB
        except AttributeError:
            pass
        return data

    @AFSDB.setter
    def AFSDB(self, AFSDB):
        if isinstance(AFSDB, Record):
            if hasattr(self, "__AFSDB"):
                logging.debug("Overwriting current record for AFSDB")
            logging.debug("Storing '%s' in AFSDB", AFSDB.name)
            self.__AFSDB = AFSDB
        else:
            raise DomainRecordsError(AFSDB,'The AFSDB domain record must be of Record class')

    @property
    def APL(self):
        data = []
        try:
            data = self.__APL
        except AttributeError:
            pass
        return data

    @APL.setter
    def APL(self, APL):
        if isinstance(APL, Record):
            if hasattr(self, "__APL"):
                logging.debug("Overwriting current record for APL")
            logging.debug("Storing '%s' in APL", APL.name)
            self.__APL = APL
        else:
            raise DomainRecordsError(APL,'The APL domain record must be of Record class')

    @property
    def CAA(self):
        data = []
        try:
            data = self.__CAA
        except AttributeError:
            pass
        return data

    @CAA.setter
    def CAA(self, CAA):
        if isinstance(CAA, Record):
            if hasattr(self, "__CAA"):
                logging.debug("Overwriting current record for CAA")
            logging.debug("Storing '%s' in CAA", CAA.name)
            self.__CAA = CAA
        else:
            raise DomainRecordsError(CAA,'The CAA domain record must be of Record class')

    @property
    def CDNSKEY(self):
        data = []
        try:
            data = self.__CDNSKEY
        except AttributeError:
            pass
        return data

    @CDNSKEY.setter
    def CDNSKEY(self, CDNSKEY):
        if isinstance(CDNSKEY, Record):
            if hasattr(self, "__CDNSKEY"):
                logging.debug("Overwriting current record for CDNSKEY")
            logging.debug("Storing '%s' in CDNSKEY", CDNSKEY.name)
            self.__CDNSKEY = CDNSKEY
        else:
            raise DomainRecordsError(CDNSKEY,'The CDNSKEY domain record must be of Record class')

    @property
    def CDS(self):
        data = []
        try:
            data = self.__CDS
        except AttributeError:
            pass
        return data

    @CDS.setter
    def CDS(self, CDS):
        if isinstance(CDS, Record):
            if hasattr(self, "__CDS"):
                logging.debug("Overwriting current record for CDS")
            logging.debug("Storing '%s' in CDS", CDS.name)
            self.__CDS = CDS
        else:
            raise DomainRecordsError(CDS,'The CDS domain record must be of Record class')

    @property
    def CERT(self):
        data = []
        try:
            data = self.__CERT
        except AttributeError:
            pass
        return data

    @CERT.setter
    def CERT(self, CERT):
        if isinstance(CERT, Record):
            if hasattr(self, "__CERT"):
                logging.debug("Overwriting current record for CERT")
            logging.debug("Storing '%s' in CERT", CERT.name)
            self.__CERT = CERT
        else:
            raise DomainRecordsError(CERT,'The CERT domain record must be of Record class')

    @property
    def CNAME(self):
        data = []
        try:
            data = self.__CNAME
        except AttributeError:
            pass
        return data

    @CNAME.setter
    def CNAME(self, CNAME):
        if isinstance(CNAME, Record):
            if hasattr(self, "__CNAME"):
                logging.debug("Overwriting current record for CNAME")
            logging.debug("Storing '%s' in CNAME", CNAME.name)
            self.__CNAME = CNAME
        else:
            raise DomainRecordsError(CNAME,'The CNAME domain record must be of Record class')

    @property
    def CSYNC(self):
        data = []
        try:
            data = self.__CSYNC
        except AttributeError:
            pass
        return data

    @CSYNC.setter
    def CSYNC(self, CSYNC):
        if isinstance(CSYNC, Record):
            if hasattr(self, "__CSYNC"):
                logging.debug("Overwriting current record for CSYNC")
            logging.debug("Storing '%s' in CSYNC", CSYNC.name)
            self.__CSYNC = CSYNC
        else:
            raise DomainRecordsError(CSYNC,'The CSYNC domain record must be of Record class')

    @property
    def DHCID(self):
        data = []
        try:
            data = self.__DHCID
        except AttributeError:
            pass
        return data

    @DHCID.setter
    def DHCID(self, DHCID):
        if isinstance(DHCID, Record):
            if hasattr(self, "__DHCID"):
                logging.debug("Overwriting current record for DHCID")
            logging.debug("Storing '%s' in DHCID", DHCID.name)
            self.__DHCID = DHCID
        else:
            raise DomainRecordsError(DHCID,'The DHCID domain record must be of Record class')

    @property
    def DLV(self):
        data = []
        try:
            data = self.__DLV
        except AttributeError:
            pass
        return data

    @DLV.setter
    def DLV(self, DLV):
        if isinstance(DLV, Record):
            if hasattr(self, "__DLV"):
                logging.debug("Overwriting current record for DLV")
            logging.debug("Storing '%s' in DLV", DLV.name)
            self.__DLV = DLV
        else:
            raise DomainRecordsError(DLV,'The DLV domain record must be of Record class')

    @property
    def DNAME(self):
        data = []
        try:
            data = self.__DNAME
        except AttributeError:
            pass
        return data

    @DNAME.setter
    def DNAME(self, DNAME):
        if isinstance(DNAME, Record):
            if hasattr(self, "__DNAME"):
                logging.debug("Overwriting current record for DNAME")
            logging.debug("Storing '%s' in DNAME", DNAME.name)
            self.__DNAME = DNAME
        else:
            raise DomainRecordsError(DNAME,'The DNAME domain record must be of Record class')

    @property
    def DNSKEY(self):
        data = []
        try:
            data = self.__DNSKEY
        except AttributeError:
            pass
        return data

    @DNSKEY.setter
    def DNSKEY(self, DNSKEY):
        if isinstance(DNSKEY, Record):
            if hasattr(self, "__DNSKEY"):
                logging.debug("Overwriting current record for DNSKEY")
            logging.debug("Storing '%s' in DNSKEY", DNSKEY.name)
            self.__DNSKEY = DNSKEY
        else:
            raise DomainRecordsError(DNSKEY,'The DNSKEY domain record must be of Record class')

    @property
    def DS(self):
        data = []
        try:
            data = self.__DS
        except AttributeError:
            pass
        return data

    @DS.setter
    def DS(self, DS):
        if isinstance(DS, Record):
            if hasattr(self, "__DS"):
                logging.debug("Overwriting current record for DS")
            logging.debug("Storing '%s' in DS", DS.name)
            self.__DS = DS
        else:
            raise DomainRecordsError(DS,'The DS domain record must be of Record class')

    @property
    def EUI(self):
        data = []
        try:
            data = self.__EUI
        except AttributeError:
            pass
        return data

    @EUI.setter
    def EUI(self, EUI):
        if isinstance(EUI, Record):
            if hasattr(self, "__EUI"):
                logging.debug("Overwriting current record for EUI")
            logging.debug("Storing '%s' in EUI", EUI.name)
            self.__EUI = EUI
        else:
            raise DomainRecordsError(EUI,'The EUI domain record must be of Record class')

    @property
    def HINFO(self):
        data = []
        try:
            data = self.__HINFO
        except AttributeError:
            pass
        return data

    @HINFO.setter
    def HINFO(self, HINFO):
        if isinstance(HINFO, Record):
            if hasattr(self, "__HINFO"):
                logging.debug("Overwriting current record for HINFO")
            logging.debug("Storing '%s' in HINFO", HINFO.name)
            self.__HINFO = HINFO
        else:
            raise DomainRecordsError(HINFO,'The HINFO domain record must be of Record class')

    @property
    def HIP(self):
        data = []
        try:
            data = self.__HIP
        except AttributeError:
            pass
        return data

    @HIP.setter
    def HIP(self, HIP):
        if isinstance(HIP, Record):
            if hasattr(self, "__HIP"):
                logging.debug("Overwriting current record for HIP")
            logging.debug("Storing '%s' in HIP", HIP.name)
            self.__HIP = HIP
        else:
            raise DomainRecordsError(HIP,'The HIP domain record must be of Record class')

    @property
    def IPSECKEY(self):
        data = []
        try:
            data = self.__IPSECKEY
        except AttributeError:
            pass
        return data

    @IPSECKEY.setter
    def IPSECKEY(self, IPSECKEY):
        if isinstance(IPSECKEY, Record):
            if hasattr(self, "__IPSECKEY"):
                logging.debug("Overwriting current record for IPSECKEY")
            logging.debug("Storing '%s' in IPSECKEY", IPSECKEY.name)
            self.__IPSECKEY = IPSECKEY
        else:
            raise DomainRecordsError(IPSECKEY,'The IPSECKEY domain record must be of Record class')

    @property
    def KEY(self):
        data = []
        try:
            data = self.__KEY
        except AttributeError:
            pass
        return data

    @KEY.setter
    def KEY(self, KEY):
        if isinstance(KEY, Record):
            if hasattr(self, "__KEY"):
                logging.debug("Overwriting current record for KEY")
            logging.debug("Storing '%s' in KEY", KEY.name)
            self.__KEY = KEY
        else:
            raise DomainRecordsError(KEY,'The KEY domain record must be of Record class')

    @property
    def KX(self):
        data = []
        try:
            data = self.__KX
        except AttributeError:
            pass
        return data

    @KX.setter
    def KX(self, KX):
        if isinstance(KX, Record):
            if hasattr(self, "__KX"):
                logging.debug("Overwriting current record for KX")
            logging.debug("Storing '%s' in KX", KX.name)
            self.__KX = KX
        else:
            raise DomainRecordsError(KX,'The KX domain record must be of Record class')

    @property
    def LOC(self):
        data = []
        try:
            data = self.__LOC
        except AttributeError:
            pass
        return data

    @LOC.setter
    def LOC(self, LOC):
        if isinstance(LOC, Record):
            if hasattr(self, "__LOC"):
                logging.debug("Overwriting current record for LOC")
            logging.debug("Storing '%s' in LOC", LOC.name)
            self.__LOC = LOC
        else:
            raise DomainRecordsError(LOC,'The LOC domain record must be of Record class')

    @property
    def MX(self):
        data = []
        try:
            data = self.__MX
        except AttributeError:
            pass
        return data

    @MX.setter
    def MX(self, MX):
        if isinstance(MX, Record):
            if hasattr(self, "__MX"):
                logging.debug("Overwriting current record for MX")
            logging.debug("Storing '%s' in MX", MX.name)
            self.__MX = MX
        else:
            raise DomainRecordsError(MX,'The MX domain record must be of Record class')

    @property
    def NAPTR(self):
        data = []
        try:
            data = self.__NAPTR
        except AttributeError:
            pass
        return data

    @NAPTR.setter
    def NAPTR(self, NAPTR):
        if isinstance(NAPTR, Record):
            if hasattr(self, "__NAPTR"):
                logging.debug("Overwriting current record for NAPTR")
            logging.debug("Storing '%s' in NAPTR", NAPTR.name)
            self.__NAPTR = NAPTR
        else:
            raise DomainRecordsError(NAPTR,'The NAPTR domain record must be of Record class')

    @property
    def NS(self):
        data = []
        try:
            data = self.__NS
        except AttributeError:
            pass
        return data

    @NS.setter
    def NS(self, NS):
        if isinstance(NS, Record):
            if hasattr(self, "__NS"):
                logging.debug("Overwriting current record for NS")
            logging.debug("Storing '%s' in NS", NS.name)
            self.__NS = NS
        else:
            raise DomainRecordsError(NS,'The NS domain record must be of Record class')

    @property
    def NSEC(self):
        data = []
        try:
            data = self.__NSEC
        except AttributeError:
            pass
        return data

    @NSEC.setter
    def NSEC(self, NSEC):
        if isinstance(NSEC, Record):
            if hasattr(self, "__NSEC"):
                logging.debug("Overwriting current record for NSEC")
            logging.debug("Storing '%s' in NSEC", NSEC.name)
            self.__NSEC = NSEC
        else:
            raise DomainRecordsError(NSEC,'The NSEC domain record must be of Record class')

    @property
    def OPENPGPKEY(self):
        data = []
        try:
            data = self.__OPENPGPKEY
        except AttributeError:
            pass
        return data

    @OPENPGPKEY.setter
    def OPENPGPKEY(self, OPENPGPKEY):
        if isinstance(OPENPGPKEY, Record):
            if hasattr(self, "__OPENPGPKEY"):
                logging.debug("Overwriting current record for OPENPGPKEY")
            logging.debug("Storing '%s' in OPENPGPKEY", OPENPGPKEY.name)
            self.__OPENPGPKEY = OPENPGPKEY
        else:
            raise DomainRecordsError(OPENPGPKEY,'The OPENPGPKEY domain record must be of Record class')

    @property
    def PTR(self):
        data = []
        try:
            data = self.__PTR
        except AttributeError:
            pass
        return data

    @PTR.setter
    def PTR(self, PTR):
        if isinstance(PTR, Record):
            if hasattr(self, "__PTR"):
                logging.debug("Overwriting current record for PTR")
            logging.debug("Storing '%s' in PTR", PTR.name)
            self.__PTR = PTR
        else:
            raise DomainRecordsError(PTR,'The PTR domain record must be of Record class')

    @property
    def RRSIG(self):
        data = []
        try:
            data = self.__RRSIG
        except AttributeError:
            pass
        return data

    @RRSIG.setter
    def RRSIG(self, RRSIG):
        if isinstance(RRSIG, Record):
            if hasattr(self, "__RRSIG"):
                logging.debug("Overwriting current record for RRSIG")
            logging.debug("Storing '%s' in RRSIG", RRSIG.name)
            self.__RRSIG = RRSIG
        else:
            raise DomainRecordsError(RRSIG,'The RRSIG domain record must be of Record class')

    @property
    def RP(self):
        data = []
        try:
            data = self.__RP
        except AttributeError:
            pass
        return data

    @RP.setter
    def RP(self, RP):
        if isinstance(RP, Record):
            if hasattr(self, "__RP"):
                logging.debug("Overwriting current record for RP")
            logging.debug("Storing '%s' in RP", RP.name)
            self.__RP = RP
        else:
            raise DomainRecordsError(RP,'The RP domain record must be of Record class')

    @property
    def SIG(self):
        data = []
        try:
            data = self.__SIG
        except AttributeError:
            pass
        return data

    @SIG.setter
    def SIG(self, SIG):
        if isinstance(SIG, Record):
            if hasattr(self, "__SIG"):
                logging.debug("Overwriting current record for SIG")
            logging.debug("Storing '%s' in SIG", SIG.name)
            self.__SIG = SIG
        else:
            raise DomainRecordsError(SIG,'The SIG domain record must be of Record class')

    @property
    def SMIMEA(self):
        data = []
        try:
            data = self.__SMIMEA
        except AttributeError:
            pass
        return data

    @SMIMEA.setter
    def SMIMEA(self, SMIMEA):
        if isinstance(SMIMEA, Record):
            if hasattr(self, "__SMIMEA"):
                logging.debug("Overwriting current record for SMIMEA")
            logging.debug("Storing '%s' in SMIMEA", SMIMEA.name)
            self.__SMIMEA = SMIMEA
        else:
            raise DomainRecordsError(SMIMEA,'The SMIMEA domain record must be of Record class')

    @property
    def SOA(self):
        data = []
        try:
            data = self.__SOA
        except AttributeError:
            pass
        return data

    @SOA.setter
    def SOA(self, SOA):
        if isinstance(SOA, Record):
            if hasattr(self, "__SOA"):
                logging.debug("Overwriting current record for SOA")
            logging.debug("Storing '%s' in SOA", SOA.name)
            self.__SOA = SOA
        else:
            raise DomainRecordsError(SOA,'The SOA domain record must be of Record class')

    @property
    def SRV(self):
        data = []
        try:
            data = self.__SRV
        except AttributeError:
            pass
        return data

    @SRV.setter
    def SRV(self, SRV):
        if isinstance(SRV, Record):
            if hasattr(self, "__SRV"):
                logging.debug("Overwriting current record for SRV")
            logging.debug("Storing '%s' in SRV", SRV.name)
            self.__SRV = SRV
        else:
            raise DomainRecordsError(SRV,'The SRV domain record must be of Record class')

    @property
    def SSHFP(self):
        data = []
        try:
            data = self.__SSHFP
        except AttributeError:
            pass
        return data

    @SSHFP.setter
    def SSHFP(self, SSHFP):
        if isinstance(SSHFP, Record):
            if hasattr(self, "__SSHFP"):
                logging.debug("Overwriting current record for SSHFP")
            logging.debug("Storing '%s' in SSHFP", SSHFP.name)
            self.__SSHFP = SSHFP
        else:
            raise DomainRecordsError(SSHFP,'The SSHFP domain record must be of Record class')

    @property
    def TA(self):
        data = []
        try:
            data = self.__TA
        except AttributeError:
            pass
        return data

    @TA.setter
    def TA(self, TA):
        if isinstance(TA, Record):
            if hasattr(self, "__TA"):
                logging.debug("Overwriting current record for TA")
            logging.debug("Storing '%s' in TA", TA.name)
            self.__TA = TA
        else:
            raise DomainRecordsError(TA,'The TA domain record must be of Record class')

    @property
    def TKEY(self):
        data = []
        try:
            data = self.__TKEY
        except AttributeError:
            pass
        return data

    @TKEY.setter
    def TKEY(self, TKEY):
        if isinstance(TKEY, Record):
            if hasattr(self, "__TKEY"):
                logging.debug("Overwriting current record for TKEY")
            logging.debug("Storing '%s' in TKEY", TKEY.name)
            self.__TKEY = TKEY
        else:
            raise DomainRecordsError(TKEY,'The TKEY domain record must be of Record class')

    @property
    def TLSA(self):
        data = []
        try:
            data = self.__TLSA
        except AttributeError:
            pass
        return data

    @TLSA.setter
    def TLSA(self, TLSA):
        if isinstance(TLSA, Record):
            if hasattr(self, "__TLSA"):
                logging.debug("Overwriting current record for TLSA")
            logging.debug("Storing '%s' in TLSA", TLSA.name)
            self.__TLSA = TLSA
        else:
            raise DomainRecordsError(TLSA,'The TLSA domain record must be of Record class')

    @property
    def TSIG(self):
        data = []
        try:
            data = self.__TSIG
        except AttributeError:
            pass
        return data

    @TSIG.setter
    def TSIG(self, TSIG):
        if isinstance(TSIG, Record):
            if hasattr(self, "__TSIG"):
                logging.debug("Overwriting current record for TSIG")
            logging.debug("Storing '%s' in TSIG", TSIG.name)
            self.__TSIG = TSIG
        else:
            raise DomainRecordsError(TSIG,'The TSIG domain record must be of Record class')

    @property
    def TXT(self):
        data = []
        try:
            data = self.__TXT
        except AttributeError:
            pass
        return data

    @TXT.setter
    def TXT(self, TXT):
        if isinstance(TXT, Record):
            if hasattr(self, "__TXT"):
                logging.debug("Overwriting current record for TXT")
            logging.debug("Storing '%s' in TXT", TXT.name)
            self.__TXT = TXT
        else:
            raise DomainRecordsError(TXT,'The TXT domain record must be of Record class')

    @property
    def URI(self):
        data = []
        try:
            data = self.__URI
        except AttributeError:
            pass
        return data

    @URI.setter
    def URI(self, URI):
        if isinstance(URI, Record):
            if hasattr(self, "__URI"):
                logging.debug("Overwriting current record for URI")
            logging.debug("Storing '%s' in URI", URI.name)
            self.__URI = URI
        else:
            raise DomainRecordsError(URI,'The URI domain record must be of Record class')

    @property
    def ZONEMD(self):
        data = []
        try:
            data = self.__ZONEMD
        except AttributeError:
            pass
        return data

    @ZONEMD.setter
    def ZONEMD(self, ZONEMD):
        if isinstance(ZONEMD, Record):
            if hasattr(self, "__ZONEMD"):
                logging.debug("Overwriting current record for ZONEMD")
            logging.debug("Storing '%s' in ZONEMD", ZONEMD.name)
            self.__ZONEMD = ZONEMD
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
            record_attribute = f'_Records__{record_type}'
            data[record_type]= str(getattr(self,record_attribute, None))
        return str(data)