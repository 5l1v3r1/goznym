#!/usr/bin/python

from Crypto.Cipher import ARC4
import base64
import argparse

def decrypt(input_filename,output_filename):
    '''
        Decrypt the main payload of a CnC response.

        Format of the payload:

        [0x0]                    unsigned char Key2Size
        [0x1]                    unsigned char PaddingSize
        [0x2]                    unsigned char [] Key2;
        [0x2+Key2Size]           unsigned int DataSize; (Encrypted)
        [0x6+Key2Size]           unsigned char [] Data; (Encrypted)
        [0x6+Key2Size+DataSize]  unsigned char [] Padding; (as many random bytes as indicated in PaddingSize)
    '''
    in_file = open(input_filename,"rb")
    data = in_file.read()
    in_file.close()
    out_file = open(output_filename,"wb")

    if data:
        #Extract the actual payload of the response
        substr = "Connection: close\r\n\r\n"
        payload = data[(data.find(substr) + len(substr)):]

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
        #Write content to output file
        out_file.write(msg)

    out_file.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Decrypt an RC4 encrypted response from the CnC')
    parser.add_argument('--input', dest='input', required=True, help='Input response payload')
    parser.add_argument('--output', dest='output', required=True, help='Output response payload')
    args = parser.parse_args()
    decrypt(args.input,args.output)
