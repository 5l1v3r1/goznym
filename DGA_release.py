import time
import struct
import binascii
import ipaddress
import struct
import socket
import re
from operator import itemgetter, attrgetter, methodcaller
from pprint import pprint

#=====================================================================================
#                                   Utility functions
#=====================================================================================

def ror(val, r_bits, max_bits):
    r_bits = r_bits % max_bits
    mask = 2**max_bits - 1
    val = val & mask
    return mask & ( (val >> r_bits) + (val << (max_bits - r_bits)))

def rol(val, r_bits, max_bits):
    r_bits = r_bits % max_bits
    mask = 2**max_bits - 1
    val = val & mask
    return mask & ( (val << r_bits) + (val >> (max_bits - r_bits)))

def bswap(temp):
    return struct.unpack("<I", struct.pack(">I", temp))[0]

def add32(a, b):
    return 0xffffffff & (a+b)
def sub32(a, b):
    return 0xffffffff & (a-b)
def add8(a, b):
    return 0xff & (a+b)
def sub8(a, b):
    return 0xff & (a-b)
    
def iptoint(ipstr):
    return (struct.unpack("<I",struct.pack(">I",int(ipaddress.ip_address(unicode(ipstr)))))[0])

def inttoip(ipint):
    strint = "%08x" % ipint
    return ".".join(str(ord(each)) for each in strint.decode("hex")[::-1])

#=====================================================================================
#                                  DGA - RNG 
#=====================================================================================

def init_rng_context(seed1, time_seed):
    '''
        Initialize RNG context
    '''
    rng_context = []
    temp = (seed1 + time_seed) & 0xffffffff
    rng_context.append(temp) 
    temp = ror(temp * 2, 4, 32)
    rng_context.append(temp)
    temp = bswap(temp)
    temp = ror(temp, 14, 32)
    temp = (temp + seed1) & 0xffffffff
    rng_context.append(temp)
    temp = temp + rng_context[1]
    temp = ror(temp, 18, 32)
    rng_context.append(temp)
    return rng_context
    
def print_context(rng_context):
    for each in rng_context:
        print hex(each)[2:-1]
        
def rng(arg1, rng_context):
    '''
        Generate random number
    '''
    t1 = (arg1 * 100) & 0xffffffff
    t2 = (rng_context[0] << 11) & 0xffffffff
    t2 = t2 ^ rng_context[0]
    rng_context[0] = (rng_context[0] + rng_context[1]) & 0xffffffff
    rng_context[1] = (rng_context[1] + rng_context[2]) & 0xffffffff
    orig_context2 = rng_context[2]
    rng_context[2] = (rng_context[2] + rng_context[3]) & 0xffffffff
    t3 = rng_context[3]
    t3 = (t3 >> 19) ^ t3 ^ t2
    t2 = (t2 >> 8)
    t3 = t3 ^ t2
    rng_context[3] = t3
    t3 = (t3 + orig_context2) & 0xffffffff
    t3 = t3 % t1
    EAX = t3 / 100
    EDX = t3 % 100
    return (rng_context, EAX, EDX)

def gen_rand_str(strtype, rng_context, rand_str_len):
    '''
        Generate random string
    '''
    rand_str = ""
    for i in xrange(rand_str_len):
        (rng_context, EAX, EDX) = rng(0xffffffff, rng_context)
        temp = EAX & 3
        if temp == 1:
            if strtype == 1:
                (rng_context, EAX, EDX) = rng(10, rng_context)
                rand_str += chr(ord("0") + EAX)
            else:
                (rng_context, EAX, EDX) = rng(26, rng_context)
                rand_str += chr(ord("a") + EAX)
        elif temp == 2:
            if strtype == 4:
                (rng_context, EAX, EDX) = rng_(26, rng_context)
                rand_str += chr(ord("A") + EAX)
            elif strtype == 1:
                (rng_context, EAX, EDX) = rng(10, rng_context)
                rand_str += chr(ord("0") + EAX)
            else:
                (rng_context, EAX, EDX) = rng(26, rng_context)
                rand_str += chr(ord("a") + EAX)
        else:
            if strtype == 2:
                (rng_context, EAX, EDX) = rng(26, rng_context)
                rand_str += chr(ord("a") + EAX)
            elif strtype == 4:
                (rng_context, EAX, EDX) = rng(26, rng_context)
                rand_str += chr(ord("A") + EAX)
            else:
                (rng_context, EAX, EDX) = rng(10, rng_context)
                rand_str += chr(ord("0") + EAX)
    return rand_str

def gen_domain(rng_context):
    '''
        Generate domain
    '''
    (rng_context, EAX, EDX) = rng(8, rng_context)
    domstrlen = 5 + EAX
    rand_str = gen_rand_str(2, rng_context, domstrlen)
    tlds = ["", "net", "com", "in", "pw"]
    tld_index = 0
    while tld_index == 0:
        (rng_context, EAX, EDX) = rng(5, rng_context)
        tld_index = EAX
    domain = rand_str+ "." + tlds[tld_index]
    return domain

def gen_domain_list(number_of_domains_to_generate,seed1,seed2,time):
    '''
        Generate list of domains, based on seeds and date
    '''
    time_seed = 0xffffffff & ((time.tm_year << 9) + (time.tm_mon << 5) + time.tm_mday)
    time_seed = (time_seed + seed1) & 0xffffffff

    rng_context = init_rng_context(seed1, time_seed)

    for i in xrange(16):
        (rng_context, EAX, EDX) = rng(0xffffffff, rng_context)
        contextind = i / 4 
        subind = i % 4
        AL = EAX & 0xff
        shiftedAL = AL << subind * 8
        bitmaskstr = ["FF"] * 4 
        bitmaskstr[3-subind] = "00"
        bitmaskstr = "".join(bitmaskstr)
        masked_dword = rng_context[contextind] & int(bitmaskstr, 16)
        rng_context[contextind] = masked_dword + shiftedAL

    for i in xrange(4): # Loop for seed2
        rng_context[i] = add32(rng_context[i],seed2)

    domainlist = []
    for i in xrange(number_of_domains_to_generate):
        domainlist.append(gen_domain(rng_context))
    return domainlist

#=====================================================================================
#                                  DGA_b variant
#=====================================================================================

def init_rng_context_b(time_seed):
    '''
        Initialize RNG context for DGA variant B
    '''
    rng_context = [0x049f635b + time_seed, 0x029401cd  + time_seed, 0x020c1182 + time_seed, 0x05c4fe35 + time_seed]
    return rng_context

def gen_rand_str_b(strtype, rng_context, rand_str_len):
    '''
        Generate random number for DGA variant B
    '''
    rand_str = ""
    for i in xrange(rand_str_len):
        temp = 1
        if temp == 1:
            if strtype == 1:
                (rng_context, EAX, EDX) = rng(10, rng_context)
                rand_str += chr(ord("0") + EAX)
            else:
                (rng_context, EAX, EDX) = rng(26, rng_context)
                rand_str += chr(ord("a") + EAX)
        elif temp == 2:
            if strtype == 4:
                (rng_context, EAX, EDX) = rng(26, rng_context)
                rand_str += chr(ord("A") + EAX)
            elif strtype == 1:
                (rng_context, EAX, EDX) = rng(10, rng_context)
                rand_str += chr(ord("0") + EAX)
            else:
                (rng_context, EAX, EDX) = rng_(26, rng_context)
                rand_str += chr(ord("a") + EAX)
        else:
            if strtype == 2:
                (rng_context, EAX, EDX) = rng(26, rng_context)
                rand_str += chr(ord("a") + EAX)
            elif strtype == 4:
                (rng_context, EAX, EDX) = rng(26, rng_context)
                rand_str += chr(ord("A") + EAX)
            else:
                (rng_context, EAX, EDX) = rng(10, rng_context)
                rand_str += chr(ord("0") + EAX)
    return rand_str

def gen_domain_b(rng_context):
    '''
        Generate domain list for DGA variant b
    '''
    (rng_context, EAX, EDX) = rng(6, rng_context)
    dom_str_len = 6 + (0xff & EAX)
    rand_str = gen_rand_str_b(2, rng_context, dom_str_len)
    tlds = ["ru", "net", "org", "com", "biz", "info"]
    tld_index = 0
    (rng_context, EAX, EDX) = rng(6, rng_context)
    tld_index = EAX
    domain = rand_str+ "." + tlds[tld_index]
    return domain

def gen_domain_list_b(number_of_domains_to_generate, time):
    '''
        Generate domain list for variant b
    '''
    time_seed = 0xffffffff & (time.tm_year + (time.tm_mon << 16) + (1 + time.tm_wday) % 7 + (time.tm_mday << 16))

    rng_context = init_rng_context_b(time_seed)

    domain_list = []
    for i in xrange(number_of_domains_to_generate):
        domain = gen_domain_b(rng_context)
        domain_list.append(domain)

    return domain_list

#=====================================================================================
#                                  IP decoding 
#=====================================================================================

def transform_ips(ips): 
    '''
    Transform the IPs returned by the second stage domain query, check the
    checksum, and return the list of IPs if everything goes OK.

    Returns: (checksum,list_of_ips)
    '''
    #First, we transform the IPs to their real representation
    ips_transformed = []
    for ip in ips:
        tmp = ip
        for i in range(0,16):
            tmp = tmp ^ 0x62192323
            tmp = sub32(tmp,0x43289501)
            tmp ^= 0x23456689
        ips_transformed.append(tmp)

    #There must be, at least, 1 IP and 1 checksum
    if len(ips) <= 1:
        return (0,None)

    #Find the checksum and remove it from the list
    #Since IPs can be resolved in any order, we compute the checksum
    #considering that any of the entries in the list can be the checksum
    #i.e., take one entry, compute the checksum of the rest of entries,
    #and compare against that entry
    ip_to_remove = None
    for i in range(0,len(ips_transformed)):
        tmp = 0
        for j in range(0,len(ips_transformed)):
            if i!=j:
                tmp = add32(tmp,ips_transformed[j])
        #If the computed checksum is equal to the current entry,
        #then the current entry is the checksum
        if tmp == ips_transformed[i]:
            ip_to_remove = i
            break
    if ip_to_remove is None:
        #The checksum was not found, there is come checksum error
        return (0,None)
    else:
        #The checksum was found, remove it from the list, 
        #and return the list of IPs
        res = ips_transformed[ip_to_remove]
        del ips_transformed[ip_to_remove]
        return (res,ips_transformed)

#=====================================================================================
#                                  IP encoding 
#=====================================================================================
 
def un_transform_ips(ips): 
    '''
    Takes a list of IPs you want the Second Stage Domain to sinkhole to. Returns a list of transformed IPs along with a transformed checksum IP.
    '''
    checksum = 0
    for ip in ips:
        tmp = iptoint(ip)
        checksum = add32(checksum, tmp)
    ips.append(inttoip(checksum))
    
    #First, we transform the IPs to their real representation
    ips_transformed = []
    for ip in ips:
        tmp = iptoint(ip)
        for i in range(0,16):
            tmp ^= 0x23456689
            tmp = add32(tmp,0x43289501)
            tmp = tmp ^ 0x62192323
        ips_transformed.append(inttoip(tmp))
    return ips_transformed


#=====================================================================================
#                                  Domain list hashing
#=====================================================================================

domain_hash_chunk ="\xBD\x84\xB4\xAA\x21\x58\xBA\x5C\x24\x14\x4E\xE6\xCE\x9F\x02\x58\x45\x10\xB0\xCC\xC2\xA7\x1C\x06\xD9\xA6\x96\x70\x5D\x22\x47\xC1\xFB\xB5\x5E\xB8\xCF\xCA\xF4\xBA\x1A\xDA\xBD\xC9\xD2\x58\x36\xD4\x73\x8B\x13\x42\x0E\x74\x56\xA1\x2F\x90\x04\x8A\xE4\x37\x50\xFE\xD7\x6B\x4B\x16\x92\x2B\x3E\x38\x14\xF7\x9E\x48\xE3\x1C\xD9\x6C\x8F\x42\xD3\xAF\x83\xC4\xE3\x18\xD5\x25\x63\xA0\x6A\x37\x29\xD4\xEF\xAE\x0B\x52\x2E\xEC\x34\x0C\x87\x57\xFC\x1E\xE6\x4A\x42\x6C\xD8\x09\xFE\xCF\xDD\xCC\x96\xCE\x90\x02\xB8\x32\xBD\x3B\xEF\x62\x6F\x63\xD0\xF1\x62\xE9\x96\xD8\xC0\x31\x6A\xA2\x25\x4F\x28\x1B\xAA\x35\x63\x3C\xDB\x77\x4F\xC4\x83\x1F\xAE\x70\x89\x3D\xB6\xA1\x96\x4C\x54\x8E\xD2\x5B\x9A\x76\xC2\x12\x60\xDF\x4E\x06\xF2\xD3\xB8\xB6\x1A\x39\x73\xC9\x81\x72\xC7\x92\xDD\x89\x72\xC8\x6B\xF2\xC0\x68\x2B\x38\x78\xB7\x23\x9D\xEC\x4D\xD5\x91\xCB\x89\x03\x62\x04\x91\x79\x63\x86\x01\x44\xAF\xBE\xFC\x4C\x2C\x52\xE6\xBE\xF9\x4A\x47\x7A\x1F\xC0\xF9\x32\xD5\x20\x56\x0E\x7E\x87\xBA\x42\xEC\x95\x6D\x8A\x40\xF4\x22\xF1\x57\xD2\x53\x0E\x8F\x75\x8B\x6F\xD0\x31\x2C\x74\x05\x88\xF4\xA8\x68\x9C\x19\x57\xDF\x30\xC9\x47\xBF\xDA\x1A\x65\xEB\x63\xA1\xBE\x22\xA1\x81\x53\xFB\x22\x55\x36\x5B\xE5\x4E\x96\x2F\xE5\x57\x77\xD2\x4F\x48\x66\x7D\xFD\x1A\x92\xC6\x88\x96\x11\xA5\x3B\x72\x68\xCD\x51\x3C\xD4\x97\xE2\xFC\xFD\xD7\x00\x4B\x2C\x5A\xE4\x56\x74\x18\x5A\x0C\x75\xE4\xE7\xE8\x6B\x9F\x03\x0F\x68\x74\xC4\x47\x3C\x28\x8F\xC1\xD4\x56\xC1\xE0\x2E\x60\xF2\xEF\xFF\x5C\xD7\x54\xD1\x50\x93\x20\x84\x43\xF9\x98\x91\xA3\x94\x36\x05\x1B\xC4\x8C\xCB\xF6\x8B\x6E\x75\xD3\x4D\x84\x8B\x17\x9F\x58\x4F\xCC\x92\x9B\x14\x8E\x22\x5A\x67\xA2\x09\xC7\xB7\xF1\xB2\xF9\x34\xA4\x2E\xE0\x12\x25\xA7\xB7\xC4\xB5\x5B\xE9\xDD\x7A\x2E\xA9\xC2\x96\x75\x17\x65\x3D\x54\x59\x93\xD7\xA2\xD2\x8A\x54\xE1\xE3\x08\x89\x19\xC9\xDB\x0C\xF1\x20\x68\x4E\x38\x7B\xFD\xD5\xAD\xDB\x91\xD5\x99\xBE\xCB\x18\xCD\x43\x78\x1A\xA1\x47\x1A\x47\x62\xF6\x6B\x46\xEB\x46\xE7\x92\x22\xF0\x4F\xB2\x78\xAD\xF1\xC0\x29\x08\x3C\x66\x52\x5B\x9B\xFD\x59\x9F\xFC\xA5\xD4\xB0\x94\xE8\x28\x83\x9C\x6B\x36\xC7\xDD\x99\x48\xEA\xDD\x37\x33\xC0\x12\xB4\xBA\x6F\xA6\x40\x70\xD5\xEE\x58\x2B\x41\xCE\xD7\x1A\xD6\x62\xDC\x0B\x90\x2C\x5E\x7D\xD9\x8C\x26\x29\x87\x67\x33\x97\xBC\xB3\x3B\x08\xC2\x55\xA9\xE9\xE7\x66\xC7\xB7\x43\x26\x1B\x92\xA1\x7C\x2E\x64\x53\x6B\x33\xD4\xC1\xC2\x98\xB0\x30\x25\x8E\x9B\x38\x3E\x9C\x6C\x2B\xB8\x3B\xA0\xD6\x0A\x25\x2B\xE8\x1C\x81\x81\x1D\xB5\x31\x6F\x5B\xDA\x5B\x66\xFA\x3C\x0D\xFE\xBC\x23\xBA\x05\xE1\x8C\x1B\x1D\x31\x13\x0E\xD6\x23\xD3\x79\x22\x17\x9F\x34\x32\xEB\x74\x33\x2B\x1C\x32\x6B\xB6\x4E\x01\x23\xF3\x9B\x2B\xD5\x08\x35\xD3\x5D\x5E\xD1\xAB\x28\x62\x91\xD1\x23\xE2\xE1\xE2\x21\xD2\x4A\xD8\x3C\x41\xE7\x2E\x80\x86\x97\x82\x21\xA7\x77\xA5\xBE\xF7\x15\xF8\xEE\x3F\x98\x36\x52\x61\x0A\x6C\x45\x89\x63\xBB\x10\x7F\x4A\x92\x49\x99\x13\x86\x3F\xE6\x3B\x35\x26\xFD\x67\xEE\x07\x1B\x38\x7F\xEA\x32\x48\xCD\x1A\x1A\x6B\x0C\xB0\x4E\x8C\xC7\x43\xA3\xF6\xCD\x74\x74\xD1\xB6\x31\x57\x79\x06\x22\x59\xDC\x86\x1D\x1B\x76\x09\x0A\x01\xCE\x73\x63\x9E\xC7\x4C\x8A\x8B\x78\x79\xA9\xDA\x25\xF7\xCD\x3E\x9B\xAE\xD4\x95\x57\xFB\x5A\x79\x28\x73\x0D\xBB\x41\x0A\xB9\xC3\x2D\x87\x38\xB0\xEC\x55\x5E\xE9\xE6\x7B\x75\x82\xDD\xC8\xCD\x60\x2A\x89\x9D\xAC\xEA\xBF\x99\xFE\x4D\x16\xF3\x20\xFA\x1E\xCD\x19\x07\x53\x72\xD6\xE4\xA5\xA0\x23\x67\xB2\xD4\x07\x9B\x24\x68\xFF\xA3\x04\xE4\x15\x40\x24\x31\x72\x64\x80\x10\x43\x8B\x14\x80\x75\x18\x09\x15\xBD\x6D\xC1\x96\x4F\x57\x02\xD1\x36\x15\xD0\x0D\xC3\xAC\xC4\xF6\x82\x4A\xFB\xD1\x7A\x64\x24\xBD\xC5\x03\x2C\x8B\x5E\x62\x4A\x6E\x87\x4F\x87\x12\x7C\xB8\xB9\xD0\x92\x7D\xB3\xE1\x14\x1B\x9E\x0A\xF7\xEE\xFD\xF0\x75\x9F\x49\x37\xF8\x57\xE5\xD3\xED\xBE\x65\x2E\xBD\x07\x74\xC9\x54\x2E\x57\x63\xB0\x78\xD0\xAC\x19\x03\xD6\xCA\x88\xD1\xA2\xD2\x2F\xE4\x20\x2C\x46\xD3\xF5\x8F\x71\x56\xDE\x9C\x3D\x87\x80\x5D\xE6\x41\x4A\xA6\x8E\x30\x9A\x0E\x48\xB4\xFD\xF6\xCA\x39\x59\xD7\x36\xA4\xC6\xE3\xF0\xF3\x1D\x2D\x09\xB5\xD5\x1E\x5A\xCC\x1F\x0D\x8D\x72\x72\xFB\x17\x3D\xC9\x70\xE2\x36\x62\x55\xB9\x3E\x3E\xDA\xDA\x7F\xDB\x6C\x3E\xB6\xC3\xB5\x6A\xEB\x2A\x7E\xCE\x92\x81\x69\x2D\x63\x02\x51\xBC\xA6\xAF\x55\x17\xB3\xBF\x90\x73\x74\x2C\x21\x39\xA5\x45\x45\x4D\xA8\x22\x95\x0D\x62\x52\x78\xDD\x47\xF6\xFC\x89\xB4\xFC\x3B\x2E\xE3\xDF\xB9\x2A\x4B\xF7\x06\x5C\x29\x8D\x77\xD1\xFC\x02\x5E\xF0\xF8\x6E\x58\x7B\xE1\x08\xD4\x59\x8B\x01\xE0\x54\x42\xF2\x5A\x4E\x3C\x57\x1C\xA0\x74\xC7\x06\xE9\x2D\x42\x5F\x9E\xA6\xDE\xEE\x7C\x6C\x74\x6A\x7C\xA9\xF2\x18\x1F\xBB\x1A\xB9\xED\x15\x4A\xEC\x78\x2A\xF1\xA7\xED\xD4\x5E\xD7\x41\x79\xED\x8E\xD3\x85\xEB\x2D\x4D\x7E\x63\xD7\x0F\xA8\xCA\x55\x51\xE4\x1A\x75\xB4\x14\x4B\x43\x70\xA8\x2E\x4E\x92\xEC\xB7\xFF\x84\xCB\x5D\x83\xA7\x47\xB5\x7C\xC7\x9C\x4D\xCC\xD5\x99\x27\x3C\xF9\xB2\x72\x84\xD8\x73\x6B\xBE\xF6\x12\xE3\x35\x9A\x85\xBA\x77\x57\xA2\xC1\xC8\xAE\x7B\x0F\x29\x7C\x56\x59\x4F\x56\xCB\xA0\xEE\xFC\xF2\x6E\x7D\x03\x2E\xDB\x0A\x95\x16\x21\x20\xA9\x63\x56\x70\xA9\xDF\xAF\x2D\x3E\xB1\x88\xF7\x68\x37\x10\x79\x6E\xBC\x63\x9B\x71\xD1\x3C\x79\xF7\xE0\x48\x02\x7D\x59\xA0\xE1\x3A\x2E\x66\xF5\xB2\xD4\xF5\x49\xDC\x45\x0F\x17\xC4\x0D\x3B\xA1\xC6\x98\x34\xF6\xE2\xF4\x81\x1A\xB8\x45\x03\xE4\x79\x86\x35\x09\x40\xB1\x41\xC9\x54\xC3\xD2\x81\xED\x45\x21\x54\xE2\x5F\x1A\xEF\xE3\x20\xC7\x84\xA2\xB0\x63\xEF\x40\x7A\x3E\xE4\xDE\xA4\x3A\x90\xDD\x76\x09\x23\x79\x5E\xA7\xD1\x0E\x92\x0B\x11\xD8\x3A\x30\x7E\x21\x8A\xE7\xA7\x15\xA3\xC9\xB3\xAD\x7E\xE3\x0B\x3E\xE9\xF4\x87\x02\x39\xC7\xDB\xAF\x33\xDB\x41\x98\x91\x77\xED\x7E\x0D\x58\x15\x09\x11\xCB\x58\x08\x2C\xC6\x18\x50\x15\x61\xD8\x90\x29\x81\xA2\x64\xF3\x5D\x9C\x3D\xD1\x1E\x39\x4B\x68\x71\x7E\x38\xBA\x28\x13\x6D\x77\x5C\xE5\x06\x9D\x75\x05\x2C\x89\x76\xFB\xDB\xA5\xBD\xE8\x99\x84\x2C\x7C\xCE\xA6\x58\x06\x9D\x60\xEF\x9A\x2C\x0E\x4B\x32\xE9\x2F\xD5\xC7\x26\xF5\x76\xB0\xC1\x38\x8F\x3F\x48\xB4\xD8\x00\x1D\xEC\x0D\xC7\x51\x7A\x79\xFF\x33\xA2\x99\x94\x8D\x2B\xAC\x8B\x00\x00\x00\x00"

def hash_domainlist(domain_list):
    '''
    Compute the hash of the complete domain list
    '''
    #Compute first crc32 of the domain list
    domain_list_str = ";".join(domain_list)
    str_to_hash = ""
    size = 0
    for c in domain_list_str:
        size +=2
        str_to_hash += c
        str_to_hash += "\x00"
    str_to_hash += ";"
    str_to_hash += "\x00"
    size += 2
    crc = binascii.crc32(str_to_hash)
    #compute second hash of the domain list
    second_hash = 0
    i = 0
    while i < size:
        c1 = ord(str_to_hash[i])
        c2 = ord(str_to_hash[i+1])
        c3 = add8(c1,c2)
        second_hash = rol(second_hash,7,32)
        c4 = (second_hash & 0xFF) ^ c3
        second_hash = (second_hash & 0xFFFFFF00) | c4
        i += 2
    return add32(crc,second_hash)

def check_if_domainset_in_list(domain_list):
    '''
        Check if a domain list is present in the hardcoded domain list
    '''
    hash_to_check = hash_domainlist(domain_list)
    i = 0
    while i < len(domain_hash_chunk):
        h = struct.unpack("<I",domain_hash_chunk[i:i+4])[0]
        if h == hash_to_check:
            return True
        i+=4
    return False

#=====================================================================================
#                              Second stage domain
#=====================================================================================

def gen_second_stage_domain(ip1, ip2, curr_time):
    '''
        Generate a second stage domain
    '''
    seed1 = struct.unpack("<I",struct.pack(">I",int(ipaddress.ip_address(unicode(ip1)))))[0]
    seed2 = struct.unpack("<I",struct.pack(">I",int(ipaddress.ip_address(unicode(ip2)))))[0]
    new_domains = gen_domain_list(0x80,seed1,seed2,curr_time)

    #Substitute the last part of the first domain
    domain_list_str = ";".join(new_domains)
    #find first .
    index = domain_list_str.find(".")
    domain_list_str = domain_list_str[0:index] + ".com;" + domain_list_str[index+5:]
    new_domains = domain_list_str.split(";")

    if check_if_domainset_in_list(new_domains):
        return new_domains[0]
    else:
        print "Domain %s not found in list" % new_domains[0]
        
    new_domains = gen_domain_list(0x80,seed2,seed1,curr_time) # Swap seeds and try again
    #Substitute the last part of the first domain
    domain_list_str = ";".join(new_domains)
    #find first .
    index = domain_list_str.find(".")
    domain_list_str = domain_list_str[0:index] + ".com;" + domain_list_str[index+5:]
    new_domains = domain_list_str.split(";")
    if check_if_domainset_in_list(new_domains):
        return new_domains[0]
    else:
        print "Domain %s not found in list" % new_domains[0]
        return None
#=====================================================================================
#                    Find days in the future with working domains 
#=====================================================================================

def find_future_domains(deltadays = 12):
    '''
        Find future domains 
    '''
    currTime = time.localtime()
    seed1 = 0xF536C78E # Hardcoded in binary
    seed2 = 0
    workingDoms = []
    for i in range(deltadays + 1): # Generate hash lists for next few days, then try to resolve them. If DNS responses contain 2 IPS, save to workingDoms
        looptime = time.strptime(str(curr_time.tm_year) + "," + str((curr_time.tm_yday + i)%366), "%Y,%j")
        dayList = gen_domain_list(15, seed1, seed2, looptime)
        for domain in day_list:
            try:
                response = socket.gethostbyname_ex(domain)
                if len(response[2]) == 2:
                    working_doms.append({"domain": domain, "response": response, "month": looptime.tm_mon, "day": looptime.tm_mday, "time": looptime})
            except Exception as e:
                print `e`
                continue
    second_stage_domains = []
    for each in working_doms:
        try:
            if len(each['response'][2]) == 2:
                ip1 = each['response'][2][0]
                ip2 = each['response'][2][1]
                ss_domain = gen_second_stage_domain(ip1, ip2, each['time'])
                second_stage_domains.append({"firststage": each['domain'], "time": each['time'], "secondstage": ss_domain})
        except Exception as e:
            print `e`
            continue
    return second_stage_domains

#=====================================================================================
#                    Find date associated with first stage domain
#=====================================================================================

def find_date_from_domain(fsdomain):
    '''
        Find the date for a domain
    '''
    curr_time = time.strptime("01 Jan 16", "%d %b %y")
    seed1 = 0xF536C78E # Hardcoded in binary
    seed2 = 0
    deltadays = 364
    answers = []
    for i in range(deltadays + 1): # Generate hash lists for next few days, then try to resolve them. If DNS responses contain 2 IPS, save to workingDoms
        looptime = time.strptime(str(curr_time.tm_year) + "," + str((curr_time.tm_yday + i)%366), "%Y,%j")
        day_list = gen_domain_list(15, seed1, seed2, looptime)
        if fsdomain in day_list:
            answers.append(['a', looptime])
    for i in range(deltadays + 1): # Generate hash lists for next few days, then try to resolve them. If DNS responses contain 2 IPS, save to workingDoms
        looptime = time.strptime(str(curr_time.tm_year) + "," + str((curr_time.tm_yday + i)%366), "%Y,%j")
        day_list_b = gen_domain_list_b(30, looptime)
        if fsdomain in day_list_b:
            answers.append(['b', looptime])
    return answers

#=====================================================================================
#                                   Demo code 
#=====================================================================================

def demo():
    '''
        Demo of the algorithm.
    '''
    # 1 Generate first list of domains: 15 domains
    seed1 = 0xF536C78E # Hardcoded in binary
    seed2 = 0
    curr_time = time.strptime("16 Mar 16", "%d %b %y")
    domains = gen_domain_list(0xF,seed1,seed2,curr_time)

    print "FIRST STAGE DOMAINS"
    print "===================\n"
    for dom in domains:
        print "    [*] %s" % dom

    # 2 Resolve IPs for this domains, in order, until we get 2 valid ips
    seed_ips = [u"205.200.49.153",u"182.53.57.197"]

    print "\n\n"
    print "SEEDS FOR SECOND STAGE"
    print "======================\n"

    for seed in seed_ips:
        print "    [*] %s" % seed

    second_stage_domain = gen_second_stage_domain(seed_ips[0], seed_ips[1], curr_time)

    #If the domain list is present in the hardcoded set of domain hashes, GenSecondStageDomain will
    #return the next domain to query. Otherwise, it will return None
    if second_stage_domain:
        print "\n\n"
        print "SECOND STAGE DOMAIN"
        print "===================\n"
        print "    [*] %s" % second_stage_domain

        #3 Query the first domain
        resolved_ips = [struct.unpack("<I",struct.pack(">I",int(ipaddress.ip_address(u"169.67.248.157"))))[0],
                        struct.unpack("<I",struct.pack(">I",int(ipaddress.ip_address(u"120.90.46.148"))))[0],
                        struct.unpack("<I",struct.pack(">I",int(ipaddress.ip_address(u"219.27.82.78"))))[0],
                        struct.unpack("<I",struct.pack(">I",int(ipaddress.ip_address(u"156.153.96.47"))))[0]]

        checksum, ip_list = transform_ips(resolved_ips)

        print "\n\n"
        print "FINAL LIST OF CNC IPS"
        print "=====================\n"

        for ip in ip_list:
            print "    [*] %s" % str(ipaddress.IPv4Address(struct.unpack("<I",struct.pack(">I",ip))[0]))
    else:
        print "Could not find the second set of domains in the hash list"


#=====================================================================================
#                                  BEGIN (MAIN) 
#=====================================================================================

demo()
dom = "lyuaswgwfxap.pw"

print "Domain: %s" % dom
for date in find_date_from_domain(dom):
    print "Variant: %s Day: %s" % (date[0],date[1])
dom = "ueaenqibeb.com"

print "Domain: %s" % dom
for date in find_date_from_domain(dom):
    print "Variant: %s Day: %s" %  (date[0],date[1])
