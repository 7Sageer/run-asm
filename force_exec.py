# %%
from capstone import *
import json
from tqdm import tqdm
import random
from multiprocessing import Process, Queue
from unicorn.x86_const import *
from unicorn import *
from keystone import *
import re


def test_single(code):
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    try:
        count = ks.asm(code)
    except:
        count = 0
    return count


def convert_hex_format(assembly):
    hex_pattern = re.compile(r'\b([0-9A-Fa-f]+)h')
    converted_assembly = hex_pattern.sub(r'0x\1', assembly)
    return converted_assembly


def get_name_value(name):

    #  match "VAR_num" label
    if name.startswith("var_"):
        match = re.match(r"var_(\d+)", name)
        if match:
            # get number
            return int(match.group(1))
    # else case
    return None


class KeypatchAsm:
    def __init__(self, arch=KS_ARCH_X86, mode=KS_MODE_64):
        self.arch = arch
        self.mode = mode
        self.ks = Ks(self.arch, self.mode)

    def fix_cmp_instruction_size(self, assembly):
        lines = assembly.split('\n')
        updated_lines = []
        for line in lines:
            if 'cmp' in line and '[' in line and ']' in line:
                # add default size indicator 'dword ptr'
                if ' ptr ' not in line:
                    line = line.replace('cmp', 'cmp dword ptr', 1)
            elif 'cmp' in line and ':' in line:
                line = 'nop'
            updated_lines.append(line)
        return '\n'.join(updated_lines)

    def replace_calls_and_leas(self, assembly):
        lines = assembly.split('\n')
        update_lines = []
        for line in lines:
            if ('call' in line) and not any(x in line for x in ['0x', '0X']):
                update_lines.append('nop')
            elif ('lea' in line):
                update_lines.append('nop')
            else:
                update_lines.append(line)
            # print(line)
        return '\n'.join(update_lines)

    def remove_comments(self, assembly):
        # remove ';'
        lines = assembly.split('\n')
        cleaned_lines = [line.split(';', 1)[0] for line in lines]
        return '\n'.join(cleaned_lines).strip()

    def replace_segment_register_references(self, assembly):
        lines = assembly.split('\n')
        updated_lines = []
        for line in lines:
            if 'cs:' in line:
                updated_lines.append('nop')
            else:
                if test_single(line) == 0 and "INSTR" not in line:
                    updated_lines.append('nop')
                else:
                    updated_lines.append(line)
        return '\n'.join(updated_lines)

    def ida_resolve(self, assembly, address):
        def _resolve(_op, ignore_kw=True):
            names = re.findall(r"[\$a-z0-9_:\.]+", _op, re.I)

            for name in names:
                # ingnore known key words
                if ignore_kw and name in ('byte', 'near', 'short', 'word', 'dword', 'ptr', 'offset'):
                    continue

                    # use get_name_value fucntion
                value = get_name_value(name)
                if value is not None:
                    _op = _op.replace(name, '0x'+str(value))

            return _op

            # split the part and anylaize each oprand
        _asm = assembly.partition(' ')
        mnem = _asm[0]
        opers = _asm[2].split(',')

        for idx, op in enumerate(opers):
            _op = list(op.partition('['))
            ignore_kw = True
            if _op[1] == '':
                _op[2] = _op[0]
                _op[0] = ''
            else:
                _op[0] = _resolve(_op[0], ignore_kw=True)
                ignore_kw = False

            _op[2] = _resolve(_op[2], ignore_kw=ignore_kw)
            opers[idx] = ''.join(_op)

        asm = "{0} {1}".format(mnem, ','.join(opers))
        return asm

    def assemble(self, assembly, address=0, syntax=KS_OPT_SYNTAX_INTEL):
        assembly = assembly.replace("endbr64\n", "")
        assembly = self.remove_comments(assembly)
        assembly = self.ida_resolve(assembly, address)
        assembly = self.replace_calls_and_leas(assembly)
        assembly = self.fix_cmp_instruction_size(assembly)
        assembly = self.replace_segment_register_references(assembly)

        def fix_ida_syntax(assembly):
            assembly = convert_hex_format(assembly)
            assembly = assembly.upper()

            assembly = assembly.replace("0X", " 0x")

            if self.arch == KS_ARCH_X86:
                if 'RETN' in assembly:
                    return assembly.replace('RETN', 'RET', 1)
                if 'OFFSET ' in assembly:
                    return assembly.replace('OFFSET ', ' ')
            return assembly

        if syntax is None:
            syntax = KS_OPT_SYNTAX_INTEL

        # print(fix_ida_syntax(assembly))
        try:
            self.ks.syntax = syntax
            encoding, count = self.ks.asm(fix_ida_syntax(assembly), address)
        except KsError as e:
            print(f"Error:{e}")
            print(f"Assembly:\n{fix_ida_syntax(assembly)}")
            print("-"*50)
            print("")
            encoding, count = None, 0

        return (encoding, count)


UC_X86_REG_MAPPING = {
    UC_X86_REG_RAX: "RAX", UC_X86_REG_RBX: "RBX", UC_X86_REG_RCX: "RCX",
    UC_X86_REG_RDX: "RDX", UC_X86_REG_RSI: "RSI", UC_X86_REG_RDI: "RDI",
    UC_X86_REG_RBP: "RBP", UC_X86_REG_RSP: "RSP", UC_X86_REG_R8: "R8",
    UC_X86_REG_R9: "R9", UC_X86_REG_R10: "R10", UC_X86_REG_R11: "R11",
    UC_X86_REG_R12: "R12", UC_X86_REG_R13: "R13", UC_X86_REG_R14: "R14",
    UC_X86_REG_R15: "R15", UC_X86_REG_RIP: "RIP",
    # FPU register, vector register and flag register
    UC_X86_REG_XMM0: "XMM0", UC_X86_REG_XMM1: "XMM1", UC_X86_REG_XMM2: "XMM2",
    UC_X86_REG_XMM3: "XMM3", UC_X86_REG_XMM4: "XMM4", UC_X86_REG_XMM5: "XMM5",
    UC_X86_REG_XMM6: "XMM6", UC_X86_REG_XMM7: "XMM7", UC_X86_REG_XMM8: "XMM8",
    UC_X86_REG_XMM9: "XMM9", UC_X86_REG_XMM10: "XMM10", UC_X86_REG_XMM11: "XMM11",
    UC_X86_REG_XMM12: "XMM12", UC_X86_REG_XMM13: "XMM13", UC_X86_REG_XMM14: "XMM14",
    UC_X86_REG_XMM15: "XMM15",
    # YMM register
    UC_X86_REG_YMM0: "YMM0", UC_X86_REG_YMM1: "YMM1", UC_X86_REG_YMM2: "YMM2",
    UC_X86_REG_YMM3: "YMM3", UC_X86_REG_YMM4: "YMM4", UC_X86_REG_YMM5: "YMM5",
    UC_X86_REG_YMM6: "YMM6", UC_X86_REG_YMM7: "YMM7", UC_X86_REG_YMM8: "YMM8",
    UC_X86_REG_YMM9: "YMM9", UC_X86_REG_YMM10: "YMM10", UC_X86_REG_YMM11: "YMM11",
    UC_X86_REG_YMM12: "YMM12", UC_X86_REG_YMM13: "YMM13", UC_X86_REG_YMM14: "YMM14",
    UC_X86_REG_YMM15: "YMM15",
    # EFLAGS register segment register
    UC_X86_REG_EFLAGS: "EFLAGS",
    UC_X86_REG_CS: "CS",
    UC_X86_REG_DS: "DS",
    UC_X86_REG_ES: "ES",
    UC_X86_REG_FS: "FS",
    UC_X86_REG_GS: "GS",
    UC_X86_REG_SS: "SS"
}


class MemoryAccessLogger:
    def __init__(self):
        self.read_accesses = []
        self.write_accesses = []

    def hook_mem_read(self, uc, access, address, size, value, user_data):
        self.read_accesses.append((address, size, value))

    def hook_mem_write(self, uc, access, address, size, value, user_data):
        self.write_accesses.append((address, size, value))


def hook_mem_invalid(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE_UNMAPPED or access == UC_MEM_READ_UNMAPPED or access == UC_MEM_FETCH_UNMAPPED:
        print(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x"
              % (address, size, value))
        start_map_addr = address & 0xfffffffffffff000

        uc.mem_map(start_map_addr, start_map_addr+0x1000)
        return True
    return True


def instruction_hook(uc, address, size, user_data):
    # get the current instruction
    code = uc.mem_read(address, size)

    rbp = uc.reg_read(UC_X86_REG_RBP)
    rsp = uc.reg_read(UC_X86_REG_RSP)
    # print(f"RBP: 0x{rbp:016x}, RSP: 0x{rsp:016x}")
    # for i in md.disasm(code, address):
    #     print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


def assemble_wrapper(asm_code, code_address, result_queue):
    """
    execute the function in new process and catch any exception to avoid crash the main process
    """
    try:
        keypatch_asm = KeypatchAsm()
        encoding, count = keypatch_asm.assemble(asm_code, code_address)
        result_queue.put((encoding, count))
    except Exception as e:
        result_queue.put((None, 0))
        print("Error during assembly:", str(e))


def safe_assemble(asm_code, code_address, timeout=3):
    result_queue = Queue()
    p = Process(target=assemble_wrapper, args=(
        asm_code, code_address, result_queue))
    p.start()
    p.join(timeout)

    if p.is_alive():
        p.terminate()
        print("Terminated the process due to timeout.")
        return None, 0

    try:
        result = result_queue.get_nowait()
        return result
    except Exception:
        return None, 0


md = Cs(CS_ARCH_X86, CS_MODE_64)


def compile_run(asm_code, code_address, seed=0):
    try:
        random.seed(seed)
        encoding, count = safe_assemble(asm_code, code_address)
        if encoding is None or count == 0:
            return "ERROR", [], []
        CODE_SIZE = (count+0x1000) // 0x1000 * 0x1000
        CODE_ADDRESS = code_address
        STACK_ADDRESS = 0x7fff0000
        STACK_SIZE = 0x2000
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(CODE_ADDRESS, CODE_ADDRESS+CODE_SIZE)
        mu.mem_map(STACK_ADDRESS, STACK_ADDRESS+STACK_SIZE)
        mu.mem_write(CODE_ADDRESS, bytes(encoding))

        mu.reg_write(UC_X86_REG_RAX, random.randint(0, 0x2000))
        mu.reg_write(UC_X86_REG_RBX, random.randint(0, 0x2000))
        mu.reg_write(UC_X86_REG_RCX, random.randint(0, 0x2000))
        mu.reg_write(UC_X86_REG_RDX, random.randint(0, 0x2000))
        mu.reg_write(UC_X86_REG_RSI, random.randint(0, 0x2000))
        mu.reg_write(UC_X86_REG_RDI, random.randint(0, 0x2000))
        mu.reg_write(UC_X86_REG_R8, random.randint(0, 0x2000))
        mu.reg_write(UC_X86_REG_R9, random.randint(0, 0x2000))
        mu.reg_write(UC_X86_REG_R10, random.randint(0, 0x2000))
        mu.reg_write(UC_X86_REG_R11, random.randint(0, 0x2000))
        mu.reg_write(UC_X86_REG_R12, random.randint(0, 0x2000))

        mu.reg_write(UC_X86_REG_RSP, STACK_ADDRESS + STACK_SIZE)
        mu.reg_write(UC_X86_REG_RBP, STACK_ADDRESS + STACK_SIZE)

        mu.hook_add(UC_HOOK_MEM_INVALID |
                    UC_HOOK_MEM_UNMAPPED, hook_mem_invalid)
        memory_logger = MemoryAccessLogger()
        mu.hook_add(UC_HOOK_MEM_READ, memory_logger.hook_mem_read)
        mu.hook_add(UC_HOOK_MEM_WRITE, memory_logger.hook_mem_write)

        mu.emu_start(CODE_ADDRESS, CODE_ADDRESS +
                     len(bytes(encoding)), timeout=0, count=1000)
        registers = {}
        for reg_id, reg_name in UC_X86_REG_MAPPING.items():
            registers[reg_name] = mu.reg_read(reg_id)
        return registers, memory_logger.read_accesses, memory_logger.write_accesses
    except Exception as e:
        return "ERROR", [], []

# %%


with open('humaneval-c-all.json', 'r') as f:
    data = json.load(f)

for item in tqdm(data):
    asm_code_raw = item['input_asm_prompt']
    
    # Clean up the assembly code
    lines = asm_code_raw.split('\n')
    if lines and lines[0].startswith('<') and lines[0].endswith('>:'):
        lines.pop(0)
    
    cleaned_lines = []
    for line in lines:
        # remove address hints like <func0+0x78>
        cleaned_lines.append(line.split('<')[0].strip())

    asm_code = '\n'.join(cleaned_lines)
    
    print(f"\n--- Executing assembly for task_id: {item['task_id']}, type: {item['type']} ---")
    regs, read_mem, write_mem = compile_run(asm_code, 0x1000, seed=0)
    
    if regs == "ERROR":
        print("Execution failed.")
    else:
        print("Registers:")
        reg_name_list = ['RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RSP', 'RBP']
        for reg_name in reg_name_list:
             if reg_name in regs:
                 print(f"  {reg_name}: {regs[reg_name]:#x}")

        if read_mem:
            print(f"Read Memory Accesses ({len(read_mem)}):")
            for addr, size, val in read_mem[:5]:
                print(f"  Read from 0x{addr:x}, size: {size}, value: 0x{val:x}")
            if len(read_mem) > 5:
                print(f"  ... and {len(read_mem) - 5} more.")
        else:
            print("No memory reads.")

        if write_mem:
            print(f"Write Memory Accesses ({len(write_mem)}):")
            for addr, size, val in write_mem[:5]:
                print(f"  Write to 0x{addr:x}, size: {size}, value: 0x{val:x}")
            if len(write_mem) > 5:
                print(f"  ... and {len(write_mem) - 5} more.")
        else:
            print("No memory writes.")
    print("-" * 50)