"""Manage host records"""

import json
import constellix
import ipaddress

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

class Domain(object):
    """Reference to a domain"""

    def __init__(self, fqdn=None, verbosity=0):
        super().__init__()
        self.__api = constellix.api(verbosity=verbosity)
        self.__verbosity=verbosity

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
                    self.name = fqdn

    def __str__(self):
        return json.dumps(dict(self), sort_keys=True, indent=4)

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
            # forward_records = getattr(self.records, record_type)
            # reverse_records = getattr(self.ptr, record_type)
            # count = 0
            # match = 0
            # known_ptrs = []
            # for reverse_record in reverse_records:
            #     known_ptrs.append(list(reverse_record.keys())[0])
            # for domain in forward_records:
            #     for value in domain.values:
            #         count += 1
            #         if value in known_ptrs:
            #             match += 1
            #         else:
            #             if not hasattr(self, "missingptrs"):
            #                 self.missingptrs = []
            #             self.missingptrs.append(value)

        return self.ptr


class Domain_PTR(object):
    """Domain PTR Records"""

    def __init__(self):
        super().__init__()
        self.A = []
        self.AAAA = []


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

class RecordHolder(object): pass

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
    	if not hasattr(self, "__A"):
    		return []
    	data = []
    	for name, record in self.__A.__dict__.items():
    		data.append(record)
    	return data

    @A.setter
    def A(self, A):
        if isinstance(A, Record):
            if not hasattr(self, "__A"):
                self.__A = RecordHolder()
            if not hasattr(A, "name"):
                raise DomainRecordsError(A,'The A domain record has no name')
            setattr(self.__A,A.name,A)
        else:
            raise DomainRecordsError(A,'The A domain record must be of Record class')

    @property
    def AAAA(self):
    	if not hasattr(self, "__AAAA"):
    		return []
    	data = []
    	for name, record in self.__AAAA.__dict__.items():
    		data.append(record)
    	return data

    @AAAA.setter
    def AAAA(self, AAAA):
        if isinstance(AAAA, Record):
            if not hasattr(self, "__AAAA"):
                self.__AAAA = RecordHolder()
            if not hasattr(AAAA, "name"):
                raise DomainRecordsError(AAAA,'The AAAA domain record has no name')
            setattr(self.__AAAA,AAAA.name,AAAA)
        else:
            raise DomainRecordsError(AAAA,'The AAAA domain record must be of Record class')

    @property
    def AFSDB(self):
    	if not hasattr(self, "__AFSDB"):
    		return []
    	data = []
    	for name, record in self.__AFSDB.__dict__.items():
    		data.append(record)
    	return data

    @AFSDB.setter
    def AFSDB(self, AFSDB):
        if isinstance(AFSDB, Record):
            if not hasattr(self, "__AFSDB"):
                self.__AFSDB = RecordHolder()
            if not hasattr(AFSDB, "name"):
                raise DomainRecordsError(AFSDB,'The AFSDB domain record has no name')
            setattr(self.__AFSDB,AFSDB.name,AFSDB)
        else:
            raise DomainRecordsError(AFSDB,'The AFSDB domain record must be of Record class')

    @property
    def APL(self):
    	if not hasattr(self, "__APL"):
    		return []
    	data = []
    	for name, record in self.__APL.__dict__.items():
    		data.append(record)
    	return data

    @APL.setter
    def APL(self, APL):
        if isinstance(APL, Record):
            if not hasattr(self, "__APL"):
                self.__APL = RecordHolder()
            if not hasattr(APL, "name"):
                raise DomainRecordsError(APL,'The APL domain record has no name')
            setattr(self.__APL,APL.name,APL)
        else:
            raise DomainRecordsError(APL,'The APL domain record must be of Record class')

    @property
    def CAA(self):
    	if not hasattr(self, "__CAA"):
    		return []
    	data = []
    	for name, record in self.__CAA.__dict__.items():
    		data.append(record)
    	return data

    @CAA.setter
    def CAA(self, CAA):
        if isinstance(CAA, Record):
            if not hasattr(self, "__CAA"):
                self.__CAA = RecordHolder()
            if not hasattr(CAA, "name"):
                raise DomainRecordsError(CAA,'The CAA domain record has no name')
            setattr(self.__CAA,CAA.name,CAA)
        else:
            raise DomainRecordsError(CAA,'The CAA domain record must be of Record class')

    @property
    def CDNSKEY(self):
    	if not hasattr(self, "__CDNSKEY"):
    		return []
    	data = []
    	for name, record in self.__CDNSKEY.__dict__.items():
    		data.append(record)
    	return data

    @CDNSKEY.setter
    def CDNSKEY(self, CDNSKEY):
        if isinstance(CDNSKEY, Record):
            if not hasattr(self, "__CDNSKEY"):
                self.__CDNSKEY = RecordHolder()
            if not hasattr(CDNSKEY, "name"):
                raise DomainRecordsError(CDNSKEY,'The CDNSKEY domain record has no name')
            setattr(self.__CDNSKEY,CDNSKEY.name,CDNSKEY)
        else:
            raise DomainRecordsError(CDNSKEY,'The CDNSKEY domain record must be of Record class')

    @property
    def CDS(self):
    	if not hasattr(self, "__CDS"):
    		return []
    	data = []
    	for name, record in self.__CDS.__dict__.items():
    		data.append(record)
    	return data

    @CDS.setter
    def CDS(self, CDS):
        if isinstance(CDS, Record):
            if not hasattr(self, "__CDS"):
                self.__CDS = RecordHolder()
            if not hasattr(CDS, "name"):
                raise DomainRecordsError(CDS,'The CDS domain record has no name')
            setattr(self.__CDS,CDS.name,CDS)
        else:
            raise DomainRecordsError(CDS,'The CDS domain record must be of Record class')

    @property
    def CERT(self):
    	if not hasattr(self, "__CERT"):
    		return []
    	data = []
    	for name, record in self.__CERT.__dict__.items():
    		data.append(record)
    	return data

    @CERT.setter
    def CERT(self, CERT):
        if isinstance(CERT, Record):
            if not hasattr(self, "__CERT"):
                self.__CERT = RecordHolder()
            if not hasattr(CERT, "name"):
                raise DomainRecordsError(CERT,'The CERT domain record has no name')
            setattr(self.__CERT,CERT.name,CERT)
        else:
            raise DomainRecordsError(CERT,'The CERT domain record must be of Record class')

    @property
    def CNAME(self):
    	if not hasattr(self, "__CNAME"):
    		return []
    	data = []
    	for name, record in self.__CNAME.__dict__.items():
    		data.append(record)
    	return data

    @CNAME.setter
    def CNAME(self, CNAME):
        if isinstance(CNAME, Record):
            if not hasattr(self, "__CNAME"):
                self.__CNAME = RecordHolder()
            if not hasattr(CNAME, "name"):
                raise DomainRecordsError(CNAME,'The CNAME domain record has no name')
            setattr(self.__CNAME,CNAME.name,CNAME)
        else:
            raise DomainRecordsError(CNAME,'The CNAME domain record must be of Record class')

    @property
    def CSYNC(self):
    	if not hasattr(self, "__CSYNC"):
    		return []
    	data = []
    	for name, record in self.__CSYNC.__dict__.items():
    		data.append(record)
    	return data

    @CSYNC.setter
    def CSYNC(self, CSYNC):
        if isinstance(CSYNC, Record):
            if not hasattr(self, "__CSYNC"):
                self.__CSYNC = RecordHolder()
            if not hasattr(CSYNC, "name"):
                raise DomainRecordsError(CSYNC,'The CSYNC domain record has no name')
            setattr(self.__CSYNC,CSYNC.name,CSYNC)
        else:
            raise DomainRecordsError(CSYNC,'The CSYNC domain record must be of Record class')

    @property
    def DHCID(self):
    	if not hasattr(self, "__DHCID"):
    		return []
    	data = []
    	for name, record in self.__DHCID.__dict__.items():
    		data.append(record)
    	return data

    @DHCID.setter
    def DHCID(self, DHCID):
        if isinstance(DHCID, Record):
            if not hasattr(self, "__DHCID"):
                self.__DHCID = RecordHolder()
            if not hasattr(DHCID, "name"):
                raise DomainRecordsError(DHCID,'The DHCID domain record has no name')
            setattr(self.__DHCID,DHCID.name,DHCID)
        else:
            raise DomainRecordsError(DHCID,'The DHCID domain record must be of Record class')

    @property
    def DLV(self):
    	if not hasattr(self, "__DLV"):
    		return []
    	data = []
    	for name, record in self.__DLV.__dict__.items():
    		data.append(record)
    	return data

    @DLV.setter
    def DLV(self, DLV):
        if isinstance(DLV, Record):
            if not hasattr(self, "__DLV"):
                self.__DLV = RecordHolder()
            if not hasattr(DLV, "name"):
                raise DomainRecordsError(DLV,'The DLV domain record has no name')
            setattr(self.__DLV,DLV.name,DLV)
        else:
            raise DomainRecordsError(DLV,'The DLV domain record must be of Record class')

    @property
    def DNAME(self):
    	if not hasattr(self, "__DNAME"):
    		return []
    	data = []
    	for name, record in self.__DNAME.__dict__.items():
    		data.append(record)
    	return data

    @DNAME.setter
    def DNAME(self, DNAME):
        if isinstance(DNAME, Record):
            if not hasattr(self, "__DNAME"):
                self.__DNAME = RecordHolder()
            if not hasattr(DNAME, "name"):
                raise DomainRecordsError(DNAME,'The DNAME domain record has no name')
            setattr(self.__DNAME,DNAME.name,DNAME)
        else:
            raise DomainRecordsError(DNAME,'The DNAME domain record must be of Record class')

    @property
    def DNSKEY(self):
    	if not hasattr(self, "__DNSKEY"):
    		return []
    	data = []
    	for name, record in self.__DNSKEY.__dict__.items():
    		data.append(record)
    	return data

    @DNSKEY.setter
    def DNSKEY(self, DNSKEY):
        if isinstance(DNSKEY, Record):
            if not hasattr(self, "__DNSKEY"):
                self.__DNSKEY = RecordHolder()
            if not hasattr(DNSKEY, "name"):
                raise DomainRecordsError(DNSKEY,'The DNSKEY domain record has no name')
            setattr(self.__DNSKEY,DNSKEY.name,DNSKEY)
        else:
            raise DomainRecordsError(DNSKEY,'The DNSKEY domain record must be of Record class')

    @property
    def DS(self):
    	if not hasattr(self, "__DS"):
    		return []
    	data = []
    	for name, record in self.__DS.__dict__.items():
    		data.append(record)
    	return data

    @DS.setter
    def DS(self, DS):
        if isinstance(DS, Record):
            if not hasattr(self, "__DS"):
                self.__DS = RecordHolder()
            if not hasattr(DS, "name"):
                raise DomainRecordsError(DS,'The DS domain record has no name')
            setattr(self.__DS,DS.name,DS)
        else:
            raise DomainRecordsError(DS,'The DS domain record must be of Record class')

    @property
    def EUI(self):
    	if not hasattr(self, "__EUI"):
    		return []
    	data = []
    	for name, record in self.__EUI.__dict__.items():
    		data.append(record)
    	return data

    @EUI.setter
    def EUI(self, EUI):
        if isinstance(EUI, Record):
            if not hasattr(self, "__EUI"):
                self.__EUI = RecordHolder()
            if not hasattr(EUI, "name"):
                raise DomainRecordsError(EUI,'The EUI domain record has no name')
            setattr(self.__EUI,EUI.name,EUI)
        else:
            raise DomainRecordsError(EUI,'The EUI domain record must be of Record class')

    @property
    def HINFO(self):
    	if not hasattr(self, "__HINFO"):
    		return []
    	data = []
    	for name, record in self.__HINFO.__dict__.items():
    		data.append(record)
    	return data

    @HINFO.setter
    def HINFO(self, HINFO):
        if isinstance(HINFO, Record):
            if not hasattr(self, "__HINFO"):
                self.__HINFO = RecordHolder()
            if not hasattr(HINFO, "name"):
                raise DomainRecordsError(HINFO,'The HINFO domain record has no name')
            setattr(self.__HINFO,HINFO.name,HINFO)
        else:
            raise DomainRecordsError(HINFO,'The HINFO domain record must be of Record class')

    @property
    def HIP(self):
    	if not hasattr(self, "__HIP"):
    		return []
    	data = []
    	for name, record in self.__HIP.__dict__.items():
    		data.append(record)
    	return data

    @HIP.setter
    def HIP(self, HIP):
        if isinstance(HIP, Record):
            if not hasattr(self, "__HIP"):
                self.__HIP = RecordHolder()
            if not hasattr(HIP, "name"):
                raise DomainRecordsError(HIP,'The HIP domain record has no name')
            setattr(self.__HIP,HIP.name,HIP)
        else:
            raise DomainRecordsError(HIP,'The HIP domain record must be of Record class')

    @property
    def IPSECKEY(self):
    	if not hasattr(self, "__IPSECKEY"):
    		return []
    	data = []
    	for name, record in self.__IPSECKEY.__dict__.items():
    		data.append(record)
    	return data

    @IPSECKEY.setter
    def IPSECKEY(self, IPSECKEY):
        if isinstance(IPSECKEY, Record):
            if not hasattr(self, "__IPSECKEY"):
                self.__IPSECKEY = RecordHolder()
            if not hasattr(IPSECKEY, "name"):
                raise DomainRecordsError(IPSECKEY,'The IPSECKEY domain record has no name')
            setattr(self.__IPSECKEY,IPSECKEY.name,IPSECKEY)
        else:
            raise DomainRecordsError(IPSECKEY,'The IPSECKEY domain record must be of Record class')

    @property
    def KEY(self):
    	if not hasattr(self, "__KEY"):
    		return []
    	data = []
    	for name, record in self.__KEY.__dict__.items():
    		data.append(record)
    	return data

    @KEY.setter
    def KEY(self, KEY):
        if isinstance(KEY, Record):
            if not hasattr(self, "__KEY"):
                self.__KEY = RecordHolder()
            if not hasattr(KEY, "name"):
                raise DomainRecordsError(KEY,'The KEY domain record has no name')
            setattr(self.__KEY,KEY.name,KEY)
        else:
            raise DomainRecordsError(KEY,'The KEY domain record must be of Record class')

    @property
    def KX(self):
    	if not hasattr(self, "__KX"):
    		return []
    	data = []
    	for name, record in self.__KX.__dict__.items():
    		data.append(record)
    	return data

    @KX.setter
    def KX(self, KX):
        if isinstance(KX, Record):
            if not hasattr(self, "__KX"):
                self.__KX = RecordHolder()
            if not hasattr(KX, "name"):
                raise DomainRecordsError(KX,'The KX domain record has no name')
            setattr(self.__KX,KX.name,KX)
        else:
            raise DomainRecordsError(KX,'The KX domain record must be of Record class')

    @property
    def LOC(self):
    	if not hasattr(self, "__LOC"):
    		return []
    	data = []
    	for name, record in self.__LOC.__dict__.items():
    		data.append(record)
    	return data

    @LOC.setter
    def LOC(self, LOC):
        if isinstance(LOC, Record):
            if not hasattr(self, "__LOC"):
                self.__LOC = RecordHolder()
            if not hasattr(LOC, "name"):
                raise DomainRecordsError(LOC,'The LOC domain record has no name')
            setattr(self.__LOC,LOC.name,LOC)
        else:
            raise DomainRecordsError(LOC,'The LOC domain record must be of Record class')

    @property
    def MX(self):
    	if not hasattr(self, "__MX"):
    		return []
    	data = []
    	for name, record in self.__MX.__dict__.items():
    		data.append(record)
    	return data

    @MX.setter
    def MX(self, MX):
        if isinstance(MX, Record):
            if not hasattr(self, "__MX"):
                self.__MX = RecordHolder()
            if not hasattr(MX, "name"):
                raise DomainRecordsError(MX,'The MX domain record has no name')
            setattr(self.__MX,MX.name,MX)
        else:
            raise DomainRecordsError(MX,'The MX domain record must be of Record class')

    @property
    def NAPTR(self):
    	if not hasattr(self, "__NAPTR"):
    		return []
    	data = []
    	for name, record in self.__NAPTR.__dict__.items():
    		data.append(record)
    	return data

    @NAPTR.setter
    def NAPTR(self, NAPTR):
        if isinstance(NAPTR, Record):
            if not hasattr(self, "__NAPTR"):
                self.__NAPTR = RecordHolder()
            if not hasattr(NAPTR, "name"):
                raise DomainRecordsError(NAPTR,'The NAPTR domain record has no name')
            setattr(self.__NAPTR,NAPTR.name,NAPTR)
        else:
            raise DomainRecordsError(NAPTR,'The NAPTR domain record must be of Record class')

    @property
    def NS(self):
    	if not hasattr(self, "__NS"):
    		return []
    	data = []
    	for name, record in self.__NS.__dict__.items():
    		data.append(record)
    	return data

    @NS.setter
    def NS(self, NS):
        if isinstance(NS, Record):
            if not hasattr(self, "__NS"):
                self.__NS = RecordHolder()
            if not hasattr(NS, "name"):
                raise DomainRecordsError(NS,'The NS domain record has no name')
            setattr(self.__NS,NS.name,NS)
        else:
            raise DomainRecordsError(NS,'The NS domain record must be of Record class')

    @property
    def NSEC(self):
    	if not hasattr(self, "__NSEC"):
    		return []
    	data = []
    	for name, record in self.__NSEC.__dict__.items():
    		data.append(record)
    	return data

    @NSEC.setter
    def NSEC(self, NSEC):
        if isinstance(NSEC, Record):
            if not hasattr(self, "__NSEC"):
                self.__NSEC = RecordHolder()
            if not hasattr(NSEC, "name"):
                raise DomainRecordsError(NSEC,'The NSEC domain record has no name')
            setattr(self.__NSEC,NSEC.name,NSEC)
        else:
            raise DomainRecordsError(NSEC,'The NSEC domain record must be of Record class')

    @property
    def OPENPGPKEY(self):
    	if not hasattr(self, "__OPENPGPKEY"):
    		return []
    	data = []
    	for name, record in self.__OPENPGPKEY.__dict__.items():
    		data.append(record)
    	return data

    @OPENPGPKEY.setter
    def OPENPGPKEY(self, OPENPGPKEY):
        if isinstance(OPENPGPKEY, Record):
            if not hasattr(self, "__OPENPGPKEY"):
                self.__OPENPGPKEY = RecordHolder()
            if not hasattr(OPENPGPKEY, "name"):
                raise DomainRecordsError(OPENPGPKEY,'The OPENPGPKEY domain record has no name')
            setattr(self.__OPENPGPKEY,OPENPGPKEY.name,OPENPGPKEY)
        else:
            raise DomainRecordsError(OPENPGPKEY,'The OPENPGPKEY domain record must be of Record class')

    @property
    def PTR(self):
    	if not hasattr(self, "__PTR"):
    		return []
    	data = []
    	for name, record in self.__PTR.__dict__.items():
    		data.append(record)
    	return data

    @PTR.setter
    def PTR(self, PTR):
        if isinstance(PTR, Record):
            if not hasattr(self, "__PTR"):
                self.__PTR = RecordHolder()
            if not hasattr(PTR, "name"):
                raise DomainRecordsError(PTR,'The PTR domain record has no name')
            setattr(self.__PTR,PTR.name,PTR)
        else:
            raise DomainRecordsError(PTR,'The PTR domain record must be of Record class')

    @property
    def RRSIG(self):
    	if not hasattr(self, "__RRSIG"):
    		return []
    	data = []
    	for name, record in self.__RRSIG.__dict__.items():
    		data.append(record)
    	return data

    @RRSIG.setter
    def RRSIG(self, RRSIG):
        if isinstance(RRSIG, Record):
            if not hasattr(self, "__RRSIG"):
                self.__RRSIG = RecordHolder()
            if not hasattr(RRSIG, "name"):
                raise DomainRecordsError(RRSIG,'The RRSIG domain record has no name')
            setattr(self.__RRSIG,RRSIG.name,RRSIG)
        else:
            raise DomainRecordsError(RRSIG,'The RRSIG domain record must be of Record class')

    @property
    def RP(self):
    	if not hasattr(self, "__RP"):
    		return []
    	data = []
    	for name, record in self.__RP.__dict__.items():
    		data.append(record)
    	return data

    @RP.setter
    def RP(self, RP):
        if isinstance(RP, Record):
            if not hasattr(self, "__RP"):
                self.__RP = RecordHolder()
            if not hasattr(RP, "name"):
                raise DomainRecordsError(RP,'The RP domain record has no name')
            setattr(self.__RP,RP.name,RP)
        else:
            raise DomainRecordsError(RP,'The RP domain record must be of Record class')

    @property
    def SIG(self):
    	if not hasattr(self, "__SIG"):
    		return []
    	data = []
    	for name, record in self.__SIG.__dict__.items():
    		data.append(record)
    	return data

    @SIG.setter
    def SIG(self, SIG):
        if isinstance(SIG, Record):
            if not hasattr(self, "__SIG"):
                self.__SIG = RecordHolder()
            if not hasattr(SIG, "name"):
                raise DomainRecordsError(SIG,'The SIG domain record has no name')
            setattr(self.__SIG,SIG.name,SIG)
        else:
            raise DomainRecordsError(SIG,'The SIG domain record must be of Record class')

    @property
    def SMIMEA(self):
    	if not hasattr(self, "__SMIMEA"):
    		return []
    	data = []
    	for name, record in self.__SMIMEA.__dict__.items():
    		data.append(record)
    	return data

    @SMIMEA.setter
    def SMIMEA(self, SMIMEA):
        if isinstance(SMIMEA, Record):
            if not hasattr(self, "__SMIMEA"):
                self.__SMIMEA = RecordHolder()
            if not hasattr(SMIMEA, "name"):
                raise DomainRecordsError(SMIMEA,'The SMIMEA domain record has no name')
            setattr(self.__SMIMEA,SMIMEA.name,SMIMEA)
        else:
            raise DomainRecordsError(SMIMEA,'The SMIMEA domain record must be of Record class')

    @property
    def SOA(self):
    	if not hasattr(self, "__SOA"):
    		return []
    	data = []
    	for name, record in self.__SOA.__dict__.items():
    		data.append(record)
    	return data

    @SOA.setter
    def SOA(self, SOA):
        if isinstance(SOA, Record):
            if not hasattr(self, "__SOA"):
                self.__SOA = RecordHolder()
            if not hasattr(SOA, "name"):
                raise DomainRecordsError(SOA,'The SOA domain record has no name')
            setattr(self.__SOA,SOA.name,SOA)
        else:
            raise DomainRecordsError(SOA,'The SOA domain record must be of Record class')

    @property
    def SRV(self):
    	if not hasattr(self, "__SRV"):
    		return []
    	data = []
    	for name, record in self.__SRV.__dict__.items():
    		data.append(record)
    	return data

    @SRV.setter
    def SRV(self, SRV):
        if isinstance(SRV, Record):
            if not hasattr(self, "__SRV"):
                self.__SRV = RecordHolder()
            if not hasattr(SRV, "name"):
                raise DomainRecordsError(SRV,'The SRV domain record has no name')
            setattr(self.__SRV,SRV.name,SRV)
        else:
            raise DomainRecordsError(SRV,'The SRV domain record must be of Record class')

    @property
    def SSHFP(self):
    	if not hasattr(self, "__SSHFP"):
    		return []
    	data = []
    	for name, record in self.__SSHFP.__dict__.items():
    		data.append(record)
    	return data

    @SSHFP.setter
    def SSHFP(self, SSHFP):
        if isinstance(SSHFP, Record):
            if not hasattr(self, "__SSHFP"):
                self.__SSHFP = RecordHolder()
            if not hasattr(SSHFP, "name"):
                raise DomainRecordsError(SSHFP,'The SSHFP domain record has no name')
            setattr(self.__SSHFP,SSHFP.name,SSHFP)
        else:
            raise DomainRecordsError(SSHFP,'The SSHFP domain record must be of Record class')

    @property
    def TA(self):
    	if not hasattr(self, "__TA"):
    		return []
    	data = []
    	for name, record in self.__TA.__dict__.items():
    		data.append(record)
    	return data

    @TA.setter
    def TA(self, TA):
        if isinstance(TA, Record):
            if not hasattr(self, "__TA"):
                self.__TA = RecordHolder()
            if not hasattr(TA, "name"):
                raise DomainRecordsError(TA,'The TA domain record has no name')
            setattr(self.__TA,TA.name,TA)
        else:
            raise DomainRecordsError(TA,'The TA domain record must be of Record class')

    @property
    def TKEY(self):
    	if not hasattr(self, "__TKEY"):
    		return []
    	data = []
    	for name, record in self.__TKEY.__dict__.items():
    		data.append(record)
    	return data

    @TKEY.setter
    def TKEY(self, TKEY):
        if isinstance(TKEY, Record):
            if not hasattr(self, "__TKEY"):
                self.__TKEY = RecordHolder()
            if not hasattr(TKEY, "name"):
                raise DomainRecordsError(TKEY,'The TKEY domain record has no name')
            setattr(self.__TKEY,TKEY.name,TKEY)
        else:
            raise DomainRecordsError(TKEY,'The TKEY domain record must be of Record class')

    @property
    def TLSA(self):
    	if not hasattr(self, "__TLSA"):
    		return []
    	data = []
    	for name, record in self.__TLSA.__dict__.items():
    		data.append(record)
    	return data

    @TLSA.setter
    def TLSA(self, TLSA):
        if isinstance(TLSA, Record):
            if not hasattr(self, "__TLSA"):
                self.__TLSA = RecordHolder()
            if not hasattr(TLSA, "name"):
                raise DomainRecordsError(TLSA,'The TLSA domain record has no name')
            setattr(self.__TLSA,TLSA.name,TLSA)
        else:
            raise DomainRecordsError(TLSA,'The TLSA domain record must be of Record class')

    @property
    def TSIG(self):
    	if not hasattr(self, "__TSIG"):
    		return []
    	data = []
    	for name, record in self.__TSIG.__dict__.items():
    		data.append(record)
    	return data

    @TSIG.setter
    def TSIG(self, TSIG):
        if isinstance(TSIG, Record):
            if not hasattr(self, "__TSIG"):
                self.__TSIG = RecordHolder()
            if not hasattr(TSIG, "name"):
                raise DomainRecordsError(TSIG,'The TSIG domain record has no name')
            setattr(self.__TSIG,TSIG.name,TSIG)
        else:
            raise DomainRecordsError(TSIG,'The TSIG domain record must be of Record class')

    @property
    def TXT(self):
    	if not hasattr(self, "__TXT"):
    		return []
    	data = []
    	for name, record in self.__TXT.__dict__.items():
    		data.append(record)
    	return data

    @TXT.setter
    def TXT(self, TXT):
        if isinstance(TXT, Record):
            if not hasattr(self, "__TXT"):
                self.__TXT = RecordHolder()
            if not hasattr(TXT, "name"):
                raise DomainRecordsError(TXT,'The TXT domain record has no name')
            setattr(self.__TXT,TXT.name,TXT)
        else:
            raise DomainRecordsError(TXT,'The TXT domain record must be of Record class')

    @property
    def URI(self):
    	if not hasattr(self, "__URI"):
    		return []
    	data = []
    	for name, record in self.__URI.__dict__.items():
    		data.append(record)
    	return data

    @URI.setter
    def URI(self, URI):
        if isinstance(URI, Record):
            if not hasattr(self, "__URI"):
                self.__URI = RecordHolder()
            if not hasattr(URI, "name"):
                raise DomainRecordsError(URI,'The URI domain record has no name')
            setattr(self.__URI,URI.name,URI)
        else:
            raise DomainRecordsError(URI,'The URI domain record must be of Record class')

    @property
    def ZONEMD(self):
    	if not hasattr(self, "__ZONEMD"):
    		return []
    	data = []
    	for name, record in self.__ZONEMD.__dict__.items():
    		data.append(record)
    	return data

    @ZONEMD.setter
    def ZONEMD(self, ZONEMD):
        if isinstance(ZONEMD, Record):
            if not hasattr(self, "__ZONEMD"):
                self.__ZONEMD = RecordHolder()
            if not hasattr(ZONEMD, "name"):
                raise DomainRecordsError(ZONEMD,'The ZONEMD domain record has no name')
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