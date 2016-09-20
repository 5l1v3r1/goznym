#!/usr/bin/python
import struct
import re
import base64
from Crypto.Cipher import ARC4
import argparse

def extract_data(cte,size,data):
    '''
        Extract HTTP Post data from each block, depending on the block type (constant)
    '''

    '''
    Machine ID [6ee5d5ff]

    +0x0  - 1E 00 00 00 (constant)
    +0x4  - A3 5F 01 00 (constant)
    +0x8  - 01 00 00 00 (global variable)
    +0xc  - 01 00 00 00 (global variable)
    +0x10 - Machineguid value.
    +0x14 - ComputerName hash
    +0x18 - cpuid based identifier (eax, xored with ecx and edx flags)
    +0x1C - Username hash 1 
    +0x20 - Username hash 2 
    +0x24 - CreateTime for process whose image name hash equals d1215f59
    +0x28 - CRC32 of the key stored in the sample 
    +0x2C - PID of process 

    System INFO [e02b4e01]

    +0x0 -0x3C OSBuildNumber
    +0x4 -0x38 OSMajorVersion
    +0x8 -0x34 OSMinorVersion
    +0xC -0x30 (isWow64 << 5) + 0x20
    +0x10 -0x2C Process fingerprint. A list of flags. Each flags is set if a given process is found in the system. Each process name is
    represented by a hash.
    +0x14 -0x28 GetSidSubAuthority - Value of the first subauthority for the process token's SID
    +0x18 -0x24 0x1 if the process is running with administrator privileges, 0x0 otherwise.
    +0x1C -0x20 Value based on system time (applies a transformation: convert to second and substract 96 years)
    +0x20 -0x1C Boot time based on  _nt_query_system_information_timeofday  (applies a transformation: convert to second and
    substract 96 years)
    +0x24 -0x18 GetSystemDefaultUILanguage
    +0x28 -0x14 GetSystemDefaultLCID
    +0x2C -0x10 

    Checksums of system info [f90670f7]

    +0x0 VolumeSerialNumber
    +0x4 GetComputerNameA (crc32)
    +0x8 GetSystemWindowsDirectory (crc32)

    Prevous config [4a6fbfd2]

    (Optional, not always in payload. It is not present for the first contact to CnC)

    Terminator constant [5af5fb76]
    '''
    if cte == 0x6ee5d5ff and size == 0x30:
        print "\n\t[%08x] Machine ID constant" % cte
        print "\t=============================="
        cte1,cte2,gvar1,gvar2,guid,comp_name,cpuid,username1,username2,createtime,pubkey,pid = struct.unpack("<IIIIIIIIIIII",data)
        print "\t\tMachine GUID: %x" % guid
        print "\t\tComputer name hash: %x" % comp_name
        print "\t\tCPUID value: %x" % cpuid
        print "\t\tUsername1 hash: %x" % username1
        print "\t\tUsername2 hash: %x" % username2
        print "\t\tCreateTime for process with image name with hash d1215f59: %x" % createtime
        print "\t\tKey hash: %x" % pubkey
        print "\t\tPID: %x" % pid

    elif cte == 0xe02b4e01 and size == 0x30:
        print "\n\t[%08x] System Info constant" % cte
        print "\t==============================="
        os_bn,os_mj,os_mn,is_64,procs,subauth,admin,time,boottime,lang,lcid = struct.unpack("<IIIIIIIIIII",data[:(0x30-0x4)])
        print "\t\t OSBuildNumber: %d" % os_bn
        print "\t\t OSMajorVersion: %d" % os_mj
        print "\t\t OSMinorVersion: %d" % os_mn
        print "\t\t 64 bit: %s" % ("True" if  (is_64 != 0x20) else "False")
        print "\t\t Running processes fingerprint: %x" % procs
        print "\t\t Subauthority: %x" % subauth
        print "\t\t Admin priviledge: %s" % "True" if (admin != 0) else "False"
        print "\t\t System time: %d" % time
        print "\t\t Time since boot %d" % boottime
        print "\t\t Default UI Language: %d" % lang
        print "\t\t Default locale: %d" % lcid

    elif cte == 0xf90670f7 and size == 0xC:
        print "\n\t[%08x] More System Info constant" % cte
        print "\t===================================="
        volsn,compname,system_dir = struct.unpack("<III",data)
        print "\t\t VolumeSerialNumber: %x" % volsn
        print "\t\t Computer name hash: %x" % compname
        print "\t\t System Windows Directory hash: %x" % system_dir

    elif cte == 0x5af5fb76:
        print "\n\t[%08x] Terminator constant found" % cte
    else:
        print "\n\t[%08x] Constant not implemented" % cte

def process_payload(file_name):
    '''
        Process an encrypted http post payload, and extract data blocks that will be 
        parsed in extract_data().
    '''

    #----------------------------------------------------------------------------------------
    #   Read the payload
    #----------------------------------------------------------------------------------------
    f = open(file_name,"r")
    sent_data = f.read()
    f.close()

    #----------------------------------------------------------------------------------------
    #   Search for the actual content of the payload, decode base64 layer 
    #----------------------------------------------------------------------------------------

    proc = re.compile("Pragma: no-cache\r\n\r\n[a-z]+=")
    m = proc.search(sent_data)
    if m:
        payload = sent_data[m.end(0):]
    else:
        print "Pattern 'Pragma: no-cache' not found"
        return

    #Fix base64 padding, if necessary
    try:
        missing_padding = 4 - len(payload) % 4
        if missing_padding:
            padded_payload = payload + b'='* missing_padding
            decoded_payload = base64.b64decode(padded_payload)
            print "Added missing padding to payload"
        else:
            decoded_payload = base64.b64decode(payload)
    except Exception as e:
        try:
            print "Trying base64 decoding again..."
            decoded_payload = base64.b64decode(payload[:-1])
        except:
            print "Could not decode the payload (base64)"
            return

    #----------------------------------------------------------------------------------------
    #   Decrypt RC4 layer of the payload 
    #----------------------------------------------------------------------------------------

    payload = decoded_payload

    #Extract parameters
    key2Size = ord(payload[0]) & 0xF
    paddingSize = ord(payload[1]) & 0xF

    #Extract encrypted content
    content = payload[(2+key2Size):(paddingSize * -1)]

    #Decrypt the encrypted content, and write it
    #Part of the key that is present in the binary
    key =  "\x63\x31\x26\x73\x6A\x64\x4A\x78\x64\x6A\x33\x6E\x48\x64\x5B\x67\x35\x26\x47\x73\x31"
    #Second part of the key is passed on the message
    key += payload[2:2+key2Size]
    #Decrypt the content using the combined key
    cipher = ARC4.new(key)
    msg = cipher.decrypt(content)

    #----------------------------------------------------------------------------------------
    #   Extract payload structure 
    #----------------------------------------------------------------------------------------

    #Current index into data buffer
    data_index = 0

    #Read the following parameters:
    # -> Total size of the block, including key1, key2 and size of the payload
    # -> key1 and key2 (these keys are only used to store the data in memory in encrypted form, but not applied when data is sent over the network) 
    # -> Size of the payload

    total_size,key1,key2,size = struct.unpack("<IIII",msg[data_index:data_index + 16])
    #Increment current index into data buffer
    data_index += 16

    #Read the data, block by block
    while (data_index - 4) < total_size:
        #Each block is formed by a constant value that determines the data type, and a size (4 bytes each)
        cte,size = struct.unpack("<II",msg[data_index:data_index + 8])
        data_index += 8
        print "\n\nConstant: %08x Size: %08x" % (cte,size)
        print "================================="
        data = msg[data_index:data_index + size]
        #Decode the contents of the block
        extract_data(cte,size,data)
        #Jump to the next block
        data_index += size
        if (data_index - 4) > total_size:
            print "Last block should have size %x, but only %x bytes available" % (size,(total_size - ((data_index - 4) - size)))

if __name__=="__main__":
    parser = argparse.ArgumentParser(description='Decrypt an RC4 encrypted query, and extract information sent to the CnC')
    parser.add_argument('--input', dest='input', required=True, help='Input query body')
    args = parser.parse_args()
    process_payload(args.input)
