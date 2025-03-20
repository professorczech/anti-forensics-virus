#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#ifdef _M_X64
#include <intrin.h>
#endif

// Function prototypes
void anti_disassembly();
void anti_debugging();
void self_modifying_code();
BOOL advanced_peb_debugger_check();

#ifdef _M_X64
// For x64 systems, define a minimal PEB structure for demonstration purposes.
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    // ... Other members are not needed for this demo.
} PEB, *PPEB;

// Definition of NtCurrentPeb for x64 builds using __readgsqword intrinsic.
PPEB NTAPI NtCurrentPeb(void) {
    // On x64, the PEB address is stored in the GS segment at offset 0x60.
    return (PPEB)__readgsqword(0x60);
}
#endif

int main() {
    printf("Starting benign program simulation...\n");

    // Demonstrate anti-disassembly techniques.
    anti_disassembly();

    // Demonstrate multiple anti-debugging techniques.
    anti_debugging();

    // Demonstrate self-modifying code.
    self_modifying_code();

    printf("Program completed successfully.\n");
    return 0;
}

//-----------------------------------------------------------------
// anti_disassembly()
// Demonstrates a simple anti-disassembly tactic by embedding data
// that confuses linear disassemblers. For x86, it uses inline assembly.
// For x64, where inline assembly is not supported by MSVC, a message is printed.
//-----------------------------------------------------------------
void anti_disassembly() {
    printf("Executing anti-disassembly technique...\n");

#ifdef _M_IX86
    __asm {
        jmp skip_data      // Jump to the label 'skip_data'
        data_section:
            db 0x90, 0x90, 0x90, 0x90  // Embed four NOP instructions as data
        skip_data:
            call data_section         // Call the address in the data section
    }
#else
    // For x64, inline assembly is not supported.
    printf("Inline assembly for anti-disassembly is not supported on x64. Skipping demonstration.\n");
#endif

    printf("Anti-disassembly technique executed.\n");
}

//-----------------------------------------------------------------
// anti_debugging()
// Uses multiple methods to detect the presence of a debugger.
// It calls standard APIs and performs an advanced PEB check.
//-----------------------------------------------------------------
void anti_debugging() {
    printf("Executing anti-debugging technique...\n");

    // Method 1: Use IsDebuggerPresent API.
    if (IsDebuggerPresent()) {
        printf("Debugger detected via IsDebuggerPresent()! Exiting program.\n");
        exit(1);
    }

    // Method 2: Use CheckRemoteDebuggerPresent API.
    BOOL debuggerFlag = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerFlag);
    if (debuggerFlag) {
        printf("Debugger detected via CheckRemoteDebuggerPresent()! Exiting program.\n");
        exit(1);
    }

    // Method 3: Advanced check via the PEB (Process Environment Block).
    if (advanced_peb_debugger_check()) {
        printf("Debugger detected via PEB check! Exiting program.\n");
        exit(1);
    }

    printf("No debugger detected. Anti-debugging technique executed.\n");
}

//-----------------------------------------------------------------
// advanced_peb_debugger_check()
// Manually reads the BeingDebugged flag from the PEB.
// On 32-bit systems, this is accessed via FS:[30h].
// On 64-bit systems, NtCurrentPeb() is used.
//-----------------------------------------------------------------
BOOL advanced_peb_debugger_check() {
#ifdef _M_IX86
    BOOL beingDebugged = FALSE;
    __asm {
        mov eax, fs:[30h]          // Load the address of the PEB from FS register
        mov al, byte ptr [eax+2]   // BeingDebugged flag is at offset 2
        mov beingDebugged, al
    }
    return beingDebugged;
#elif defined(_M_X64)
    // On x64, use NtCurrentPeb which we've defined.
    PPEB peb = NtCurrentPeb();
    return peb->BeingDebugged;
#else
    return FALSE;
#endif
}

//-----------------------------------------------------------------
// self_modifying_code()
// Demonstrates self-modifying code by allocating executable memory,
// copying a small routine that calls MessageBoxA, executing it,
// and then modifying the code to change its behavior at runtime.
//-----------------------------------------------------------------
void self_modifying_code() {
    printf("Executing self-modifying code technique...\n");

    // Allocate memory with execute, read, and write permissions.
    unsigned char *code = (unsigned char *)VirtualAlloc(NULL, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (code == NULL) {
        printf("Memory allocation failed.\n");
        exit(1);
    }

    // Define the original machine code that calls MessageBoxA to display "Hello, World!".
    // Code layout:
    //   push 0                    ; MB_OK
    //   push offset "Hello, World!"
    //   push offset "Message"
    //   push 0                    ; hWnd = NULL
    //   call MessageBoxA          ; call the API function
    //   ret                       ; return
    unsigned char original_code[] = {
        0x6A, 0x00,                   // push 0 (MB_OK)
        0x68, 0, 0, 0, 0,             // push offset for "Hello, World!"
        0x68, 0, 0, 0, 0,             // push offset for "Message"
        0x6A, 0x00,                   // push 0 (NULL hWnd)
        0xE8, 0, 0, 0, 0,             // call MessageBoxA (relative address)
        0xC3                          // ret
    };

    // String literals used by the code.
    char *hello_world = "Hello, World!";
    char *message = "Message";

    // Insert string pointers into the machine code.
    *(char **)(original_code + 3) = hello_world;
    *(char **)(original_code + 8) = message;

#ifdef _WIN64
    DWORD_PTR callOffset = (DWORD_PTR)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA") - ((DWORD_PTR)code + 14);
#else
    DWORD callOffset = (DWORD)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA") - ((DWORD)code + 14);
#endif
    *(DWORD_PTR *)(original_code + 11) = callOffset;

    // Copy the original code into the allocated memory.
    memcpy(code, original_code, sizeof(original_code));

    // Execute the code: this shows a message box with "Hello, World!".
    ((void(*)())code)();

    // --- Self-modification step ---
    // Modify the code in memory to change the string from "Hello, World!" to "Goodbye!".
    char *goodbye = "Goodbye!";
    *(char **)(code + 3) = goodbye;

    // Execute the modified code: now the message box displays "Goodbye!".
    ((void(*)())code)();

    // Release the allocated memory.
    VirtualFree(code, 0, MEM_RELEASE);

    printf("Self-modifying code technique executed.\n");
}
