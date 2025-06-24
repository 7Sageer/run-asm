import re
import subprocess
import tempfile
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KsError, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT
import struct

def clean_asm(code):
    """Cleans assembly code by removing comments, blank lines, and unnecessary assembler directives."""
    lines = []
    # Extended list of directives to remove for cleaner assembly, especially from GCC.
    directives_to_remove = (
        '.file', '.ident', '.size', '.section', '.globl', '.type', '.text', 
        '.cfi_startproc', '.cfi_endproc', '.cfi_def_cfa_offset', '.cfi_offset', 
        '.cfi_def_cfa_register', '.cfi_def_cfa', '.note.GNU-stack', '.string'
    )
    
    for line in code.strip().split('\n'):
        # Strip comments (for GAS, it's '#')
        line = line.split('#')[0].strip()

        if not line:
            continue
            
        # Keystone-specific fix for .long directive.
        # It seems to have issues with large integer literals.
        # We'll convert .long to a sequence of .byte directives.
        match = re.match(r'\.long\s+(-?\d+)', line)
        if match:
            val = int(match.group(1))
            try:
                # Pack as a signed 32-bit little-endian integer.
                packed_bytes = struct.pack('<l', val)
                byte_str = ", ".join(f"0x{b:02x}" for b in packed_bytes)
                line = f".byte {byte_str}"
            except struct.error:
                # If packing fails, leave the line as is.
                pass

        # Filter out only unnecessary assembler directives
        if not line.startswith(directives_to_remove) and not line.startswith('.LFE') and not re.match(r'^\d+:', line):
            lines.append(line)
            
    # Join the cleaned lines into a single string for Keystone
    return "\n".join(lines)

def compile_c_to_asm(c_code, optimization='O0'):
    """Compiles a string of C code to AT&T assembly using GCC."""
    # Use a temporary file to store the C code
    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as c_file:
        c_file.write(c_code)
        c_file_path = c_file.name

    s_file_path = c_file_path.replace('.c', '.s')
    
    try:
        # Invoke GCC to compile the C file to an assembly file (-S)
        # -masm=att is redundant for GCC on Linux but ensures AT&T syntax
        # Add -fcf-protection=none to disable CET instructions like endbr64
        subprocess.run(
            ['gcc', '-S', f'-{optimization}', '-fcf-protection=none', c_file_path, '-o', s_file_path],
            check=True, capture_output=True, text=True
        )
        with open(s_file_path, 'r') as f:
            asm_code = f.read()
        return asm_code
    except subprocess.CalledProcessError as e:
        print(f"GCC compilation failed for optimization {optimization}:")
        print(e.stderr)
        return None
    finally:
        # Clean up the temporary C and Assembly files
        import os
        os.remove(c_file_path)
        if os.path.exists(s_file_path):
            os.remove(s_file_path)

def assemble(asm_code, base_address=0x10000):
    """Assembles AT&T assembly code into machine code using Keystone."""
    try:
        # Initialize Keystone for x86-64 architecture
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        # IMPORTANT: Set syntax to AT&T, as it's the output format of GCC
        ks.syntax = KS_OPT_SYNTAX_ATT
        
        # Clean the assembly code before assembling
        cleaned_asm = clean_asm(asm_code)
        
        # Perform the assembly
        encoding, count = ks.asm(cleaned_asm, base_address)
        print(f"Successfully assembled {count} instructions.")
        if not encoding:
            print("No encoding found. Returning None.")
            return None
        return bytes(encoding)
    except KsError as e:
        print(f"Keystone assembly failed: {e}")
        # Print the cleaned assembly that caused the error for debugging
        print("\n--- Failing Assembly Code (Cleaned) ---")
        print(cleaned_asm)
        print("---------------------------------------")
        return None 