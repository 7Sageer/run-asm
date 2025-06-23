import struct
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import *

class Emulator:
    """A class to emulate x86-64 machine code using Unicorn."""

    def __init__(self):
        # Memory layout constants - Redesigned to prevent overlap
        self.CODE_ADDRESS = 0x10000
        self.STACK_ADDRESS = 0x30000
        self.DATA_ADDRESS_START = 0x200000  # Moved data section to a higher address
        self.EXIT_ADDRESS = 0xF00000  # Moved exit address far away

        # Memory layout constants
        self.STACK_SIZE = 1024 * 8
        
        # Initialize Unicorn engine
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)

        # Allocate memory for code, data, stack, and an exit point
        self.mu.mem_map(self.CODE_ADDRESS, 4 * 1024)
        self.mu.mem_map(self.DATA_ADDRESS_START, 1024 * 1024)  # 1MB for data
        self.mu.mem_map(self.STACK_ADDRESS, self.STACK_SIZE)
        self.mu.mem_map(self.EXIT_ADDRESS, 4 * 1024)

    def _pack_value(self, value, data_type):
        """Packs a Python value into bytes according to its C type."""
        if data_type == 'char':
            # In C, char is a 1-byte integer.
            # The value could be a string of length 1 or an integer.
            if isinstance(value, str):
                return struct.pack('<b', ord(value[0]))
            return struct.pack('<b', value)  # signed char
        elif data_type == 'bool':
            # In C, bool is a 1-byte integer.
            return struct.pack('<?', value)
        elif data_type == 'int':
            return struct.pack('<i', value)
        elif data_type == 'long':
            return struct.pack('<q', value)
        elif data_type == 'float':
            return struct.pack('<f', value)
        elif data_type == 'double':
            return struct.pack('<d', value)
        else:
            raise TypeError(f"Unsupported data type for packing: {data_type}")

    def _prepare_args(self, signature, args):
        """Sets up registers and memory for function arguments based on System V AMD64 ABI."""
        if len(signature['arg_types']) != len(args):
            raise ValueError(
                f"Argument count mismatch for function {signature['name']}: "
                f"expected {len(signature['arg_types'])}, got {len(args)}"
            )
        # ABI specified registers for arguments
        int_regs = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
        float_regs = [UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3,
                      UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7]
        int_idx, float_idx = 0, 0
        
        # Keep track of memory to allocate for pointers
        next_data_addr = self.DATA_ADDRESS_START

        for arg_type, arg_val in zip(signature['arg_types'], args):
            is_pointer = '*' in arg_type
            base_type = arg_type.replace('*', '').strip()

            if is_pointer:
                # For pointers, write data to memory and put address in a register
                if not isinstance(arg_val, (list, tuple)):
                    raise TypeError(f"Argument for pointer type {arg_type} must be a list or tuple.")
                
                array_bytes = b''.join(self._pack_value(item, base_type) for item in arg_val)
                self.mu.mem_write(next_data_addr, array_bytes)
                self.mu.reg_write(int_regs[int_idx], next_data_addr)
                
                next_data_addr += len(array_bytes)
                # Align next address to 8 bytes for simplicity
                if next_data_addr % 8 != 0:
                    next_data_addr += 8 - (next_data_addr % 8)
                int_idx += 1
            
            elif base_type in ['float', 'double']:
                # Floating point arguments go into XMM registers
                if float_idx >= len(float_regs):
                    raise ValueError("Too many floating point arguments for registers.")
                
                # Pack the float/double and write it to the XMM register
                packed_val = self._pack_value(arg_val, base_type)
                # XMM registers are 128-bit, so we pad the value
                padded_val_bytes = packed_val.ljust(16, b'\x00')
                # Unicorn expects a single large integer for XMM registers
                val_int = int.from_bytes(padded_val_bytes, 'little')
                self.mu.reg_write(float_regs[float_idx], val_int)
                float_idx += 1

            else: # Integer types
                if int_idx >= len(int_regs):
                    raise ValueError("Too many integer arguments for registers.")
                self.mu.reg_write(int_regs[int_idx], arg_val)
                int_idx += 1

    def run(self, machine_code, signature, args):
        """Executes the given machine code with specified arguments and signature."""
        # 1. Write machine code to its designated memory area
        self.mu.mem_write(self.CODE_ADDRESS, machine_code)

        # 2. Set up the stack pointer and place the exit address on the stack
        rsp = self.STACK_ADDRESS + self.STACK_SIZE - 8
        self.mu.reg_write(UC_X86_REG_RSP, rsp)
        self.mu.mem_write(rsp, self.EXIT_ADDRESS.to_bytes(8, 'little'))

        # 3. Prepare registers and memory with function arguments
        self._prepare_args(signature, args)
        
        # 4. Define a hook to stop emulation when the function returns (to our exit address)
        def stop_on_exit(uc, address, size, user_data):
            if address == self.EXIT_ADDRESS:
                uc.emu_stop()
        
        hook = self.mu.hook_add(UC_HOOK_CODE, stop_on_exit, begin=self.EXIT_ADDRESS, end=self.EXIT_ADDRESS)

        # 5. Start emulation from the beginning of the code
        try:
            self.mu.emu_start(self.CODE_ADDRESS, self.CODE_ADDRESS + len(machine_code))
        except UcError as e:
            print(f"Unicorn emulation error: {e}")
            self.print_registers()
            return None
        finally:
            self.mu.hook_del(hook)

        # 6. Retrieve the result from the correct register based on the return type
        return_type = signature['return_type']
        if return_type in ['int', 'long', 'bool'] or '*' in return_type:
            # Integer and pointer results are in RAX
            raw_result = self.mu.reg_read(UC_X86_REG_RAX)
            # Ensure we respect C's 32-bit int size if applicable
            if return_type == 'int':
                return struct.unpack('<i', struct.pack('<I', raw_result & 0xFFFFFFFF))[0]
            return raw_result
        elif return_type in ['float', 'double']:
            # Floating point results are in XMM0, returned as a large integer
            xmm0_int = self.mu.reg_read(UC_X86_REG_XMM0)
            xmm0_bytes = xmm0_int.to_bytes(16, 'little')
            if return_type == 'float':
                return struct.unpack('<f', xmm0_bytes[:4])[0]
            else: # double
                return struct.unpack('<d', xmm0_bytes[:8])[0]
        else:
            raise TypeError(f"Unsupported return type: {return_type}")

    def print_registers(self):
        """A utility function to print the state of all general-purpose and XMM registers."""
        print("\n--- Register State ---")
        # Print general-purpose registers
        for reg in ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", 
                    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP"]:
            reg_id = globals()[f"UC_X86_REG_{reg}"]
            val = self.mu.reg_read(reg_id)
            print(f"{reg:<4}: 0x{val:016x} ({val})")
        # Print the first 8 XMM registers
        for i in range(8):
            reg_id = globals()[f"UC_X86_REG_XMM{i}"]
            val_int = self.mu.reg_read(reg_id)
            val_bytes = val_int.to_bytes(16, 'little')
            print(f"XMM{i:<2}: {val_bytes.hex()}")
        print("-" * 22) 