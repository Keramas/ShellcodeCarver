# Shellcode Carver Script

This python script is for carving out shellcode into the EAX register in situations when standard encoding methods are not possible due to the bad characters.

## Usage Instructions

### 1. Verify bad characters that cannot be used and add them to the "badChar" list in the Python script

Example:

`
badChar=[0x00, 0x0a, 0x0d]
`


### 2. Define the target values based on shellcode you wish to encode. 

How to do this:

A full explanation on the encoding process has been written by Vellosec [1].

The target address is the result of the following equation:

0xFFFFFFFF - [4 byte shellcode] + 1 = Target address


Example using 4 bytes from Matt Miller's Egghunter shellcode (\xe7\xff\xe7\x75):
FFFFFFFF - E7FFE775 + 1 = 1800188B


Add or remove sets as needed depending on your shellcode



### 3. Find out your current ESP location and the address where you want the decoding to take place

In the location where you will be placing this shellcode, first place the following ASM instructions:

`
PUSH ESP

POP EAX
`

Step through the code and note what the ESP address is after the POP EAX instruction. This is the "current ESP address". 
When running the script, input this value when asked, followed by the value of the address you wish to decode.



### 4. Modify the genShellcode() function for your shellcode below "Begin actual shellcode encoding:" by calling the encoding functions as needed for your target addresses.

Four different functions:

- encodeNorm(set#) - Use when no null bytes present in target address
- encodeNullFirst(set#) - Use when first byte of target is a null byte
- encodeNullSecond(set#) - Use when second byte of target is a null byte
- encodeNullThird(set#) - Use when third byte of target is a null byte


## References:
- [1]Vellosec - CARVING SHELLCODE USING RESTRICTIVE CHARACTER SETS 
https://vellosec.net/2018/08/carving-shellcode-using-restrictive-character-sets/


- [2]NNM Zero-day by Muts
https://www.youtube.com/watch?v=gHISpAZiAm0

