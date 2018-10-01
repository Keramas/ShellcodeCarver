# EgghunterShellcodeCarver

This python script is for carving out Matt Miller's 32 byte egghunter shellcode into the EAX register in situations when standard encoding methods are not possible due to the amount of severely restricted characters.

<b>How to use:</b>

-Modify the script by adding the bad characters you have discovered to the badChar list.
-The egg is predefined as 'W00T' for the shellcode.
-Modify the memory address where the decoding will begin in the genShellcode function.

<b>Technique references:</b>
NNM Zero-day by Muts:
https://www.youtube.com/watch?v=gHISpAZiAm0

Very nice explanation:
https://vellosec.net/2018/08/carving-shellcode-using-restrictive-character-sets/
