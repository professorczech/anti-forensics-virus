#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#ifdef _M_X64
#include <intrin.h>
#endif

// Function prototypes
void anti_disassembly();
void opaque_predicate_demo();
void anti_debugging();
void hardware_debug_check();
void runtime_decompression_demo();
void self_modifying_code();
BOOL advanced_peb_debugger_check();

#ifdef _M_X64
// For x64 systems, define a minimal PEB structure for demonstration.
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    // Other members omitted for brevity.
} PEB, *PPEB;

// Definition of NtCurrentPeb for x64 using the __readgsqword intrinsic.
PPEB NTAPI NtCurrentPeb(void) {
    // On x64, the PEB address is stored in the GS segment at offset 0x60.
    return (PPEB)__readgsqword(0x60);
}
#endif

int main() {
    printf("Starting benign program simulation...\n");

    // 8.1.1 Misaligned Disassembly demonstration.
    anti_disassembly();

    // 8.1.2 Opaque Predicates demonstration.
    opaque_predicate_demo();

    // 8.2.1 & 8.2.2 API-Based and Process/Thread Debugging checks.
    anti_debugging();

    // 8.2.3 Hardware-Based Debugging Check.
    hardware_debug_check();

    // 8.3.1 Runtime Decompression demonstration.
    runtime_decompression_demo();

    // 8.3.2 Self-Modifying Code demonstration.
    self_modifying_code();

    printf("Program completed successfully.\n");
    return 0;
}

//-----------------------------------------------------------------
// anti_disassembly()
// Demonstrates a misaligned disassembly tactic by embedding data that
// can mislead linear disassemblers. On x86, inline assembly is used;
// on x64, a message is printed.
//-----------------------------------------------------------------
void anti_disassembly() {
    printf("Executing anti-disassembly technique...\n");

#ifdef _M_IX86
    __asm {
        jmp skip_data      // Jump to skip the data section.
        data_section:
            db 0x90, 0x90, 0x90, 0x90  // Four NOP instructions treated as data.
        skip_data:
            call data_section         // Call the address in the data section.
    }
#else
    printf("Inline assembly for anti-disassembly is not supported on x64. Skipping demonstration.\n");
#endif

    printf("Anti-disassembly technique executed.\n");
}

//-----------------------------------------------------------------
// opaque_predicate_demo()
// Demonstrates an opaque predicate that always evaluates to true,
// but appears nontrivial to an analyst.
//-----------------------------------------------------------------
void opaque_predicate_demo() {
    printf("Executing opaque predicate demonstration...\n");
    int x = 10;
    // This condition always evaluates to true, but its expression looks complex.
    if ((x * x + x) % 2 == 0) {
        printf("Opaque predicate evaluated to true: printing 'Hello, World!'\n");
    } else {
        printf("Opaque predicate evaluated to false: this should never happen.\n");
    }
    printf("Opaque predicate demonstration executed.\n");
}

//-----------------------------------------------------------------
// anti_debugging()
// Uses multiple methods (API calls and PEB check) to detect the presence of a debugger.
//-----------------------------------------------------------------
void anti_debugging() {
    printf("Executing anti-debugging technique...\n");

    // Method 1: API-based check.
    if (IsDebuggerPresent()) {
        printf("Debugger detected via IsDebuggerPresent()! Exiting program.\n");
        exit(1);
    }

    // Method 2: Process/thread check.
    BOOL debuggerFlag = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerFlag);
    if (debuggerFlag) {
        printf("Debugger detected via CheckRemoteDebuggerPresent()! Exiting program.\n");
        exit(1);
    }

    // Method 3: Advanced PEB check.
    if (advanced_peb_debugger_check()) {
        printf("Debugger detected via PEB check! Exiting program.\n");
        exit(1);
    }

    printf("No debugger detected. Anti-debugging technique executed.\n");
}

//-----------------------------------------------------------------
// hardware_debug_check()
// Demonstrates hardware-based debugging checks by manipulating CPU registers.
// On x86, inline assembly sets the Trap Flag (TF); on x64, the feature is unavailable.
//-----------------------------------------------------------------
void hardware_debug_check() {
    printf("Executing hardware-based debug check...\n");
#ifdef _M_IX86
    __asm {
        pushfd            // Push EFLAGS onto the stack.
        pop eax           // Pop EFLAGS into EAX.
        or eax, 0x100     // Set the Trap Flag (TF) (8th bit) in EAX.
        push eax          // Push modified EAX back onto the stack.
        popfd             // Pop back into EFLAGS.
        nop               // Execute a no-op, which triggers a single-step interrupt if under debugging.
    }
    printf("Hardware-based debug check executed (x86 inline assembly).\n");
#elif defined(_M_X64)
    printf("Hardware-based debug check via inline assembly is not supported on x64. Skipping demonstration.\n");
#else
    printf("Unsupported architecture for hardware-based debug check.\n");
#endif
}

//-----------------------------------------------------------------
// decompress_payload()
// A dummy decompression function that simulates decompression logic.
// For demonstration, it writes a fixed string into the output buffer.
//-----------------------------------------------------------------
void decompress_payload(unsigned char *output, size_t out_size) {
    const char *payload = "Decompressed Payload Executed!";
    size_t len = strlen(payload) + 1;
    if (len > out_size) len = out_size;
    memcpy(output, payload, len);
}

//-----------------------------------------------------------------
// runtime_decompression_demo()
// Demonstrates runtime decompression by allocating executable memory,
// decompressing a dummy payload, and "executing" it by printing the result.
//-----------------------------------------------------------------
void runtime_decompression_demo() {
    printf("Executing runtime decompression demonstration...\n");
    size_t decompressed_size = 128;
    unsigned char *decompressed_code = (unsigned char *)VirtualAlloc(NULL, decompressed_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (decompressed_code == NULL) {
        printf("Memory allocation for decompression failed.\n");
        return;
    }
    // Simulate decompression
    decompress_payload(decompressed_code, decompressed_size);
    // For demonstration, print the decompressed payload.
    printf("%s\n", (char *)decompressed_code);
    VirtualFree(decompressed_code, 0, MEM_RELEASE);
    printf("Runtime decompression demonstration executed.\n");
}

//-----------------------------------------------------------------
// self_modifying_code()
// Demonstrates self-modifying code by allocating executable memory,
// copying a small routine that calls MessageBoxA, executing it,
// then modifying the code to change its behavior at runtime.
//-----------------------------------------------------------------
void self_modifying_code() {
    printf("Executing self-modifying code technique...\n");

    // Allocate memory with execute, read, and write permissions.
    unsigned char *code = (unsigned char *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (code == NULL) {
        printf("Memory allocation failed.\n");
        exit(1);
    }

    // Define machine code that calls MessageBoxA to display "Hello, World!".
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

    // Execute the code: displays a message box with "Hello, World!".
    ((void(*)())code)();

    // --- Self-modification step ---
    // Modify the code in memory to change the string to "Goodbye!".
    char *goodbye = "Goodbye!";
    *(char **)(code + 3) = goodbye;

    // Execute the modified code: now the message box displays "Goodbye!".
    ((void(*)())code)();

    // Release the allocated memory.
    VirtualFree(code, 0, MEM_RELEASE);

    printf("Self-modifying code technique executed.\n");
}

//-----------------------------------------------------------------
// advanced_peb_debugger_check()
// Reads the BeingDebugged flag from the PEB. Uses inline assembly on x86
// and NtCurrentPeb on x64.
//-----------------------------------------------------------------
BOOL advanced_peb_debugger_check() {
#ifdef _M_IX86
    BOOL beingDebugged = FALSE;
    __asm {
        mov eax, fs:[30h]          // Load PEB address from FS register.
        mov al, byte ptr [eax+2]   // BeingDebugged flag at offset 2.
        mov beingDebugged, al
    }
    return beingDebugged;
#elif defined(_M_X64)
    PPEB peb = NtCurrentPeb();
    return peb->BeingDebugged;
#else
    return FALSE;
#endif
}
