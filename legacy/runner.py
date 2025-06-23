import sys
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_ERR_ARG
from unicorn.x86_const import *

# --- 配置 ---
# 从 'sum.bin' 文件中动态读取机器码
try:
    with open('sum.bin', 'rb') as f:
        SUM_ARRAY_CODE = f.read()
except FileNotFoundError:
    print("错误: 未找到 'sum.bin' 文件。")
    print("请先运行 'assembly.py' 来生成机器码文件。")
    sys.exit(1)

# 内存布局
CODE_ADDRESS = 0x10000   # 代码加载的基地址
ARRAY_ADDRESS = 0x20000  # 存放输入数组的地址
STACK_ADDRESS = 0x30000  # 堆栈的起始地址
STACK_SIZE = 1024 * 8    # 8KB 的堆栈大小
EXIT_ADDRESS = 0x100000 # ret指令返回的安全地址，必须页对齐

# 输入数据
INPUT_ARRAY = [10, 20, 30, 40, -50]
ARRAY_COUNT = len(INPUT_ARRAY)

def print_registers(mu):
    """打印所有通用寄存器的值"""
    print("--- Register State ---")
    registers = {
        "RAX": mu.reg_read(UC_X86_REG_RAX), "RBX": mu.reg_read(UC_X86_REG_RBX),
        "RCX": mu.reg_read(UC_X86_REG_RCX), "RDX": mu.reg_read(UC_X86_REG_RDX),
        "RSI": mu.reg_read(UC_X86_REG_RSI), "RDI": mu.reg_read(UC_X86_REG_RDI),
        "RBP": mu.reg_read(UC_X86_REG_RBP), "RSP": mu.reg_read(UC_X86_REG_RSP),
        "R8": mu.reg_read(UC_X86_REG_R8),   "R9": mu.reg_read(UC_X86_REG_R9),
        "R10": mu.reg_read(UC_X86_REG_R10), "R11": mu.reg_read(UC_X86_REG_R11),
        "R12": mu.reg_read(UC_X86_REG_R12), "R13": mu.reg_read(UC_X86_REG_R13),
        "R14": mu.reg_read(UC_X86_REG_R14), "R15": mu.reg_read(UC_X86_REG_R15),
        "RIP": mu.reg_read(UC_X86_REG_RIP)
    }
    for reg, val in registers.items():
        print(f"{reg:<4}: 0x{val:016x} ({val})")

# --- 主执行流程 ---
try:
    # 1. 初始化 Unicorn 模拟器
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # 2. 分配和映射内存
    #    - 代码段
    mu.mem_map(CODE_ADDRESS, 4 * 1024) # 4KB for code
    #    - 数据段 (用于数组)
    mu.mem_map(ARRAY_ADDRESS, 4 * 1024) # 4KB for array data
    #    - 堆栈段
    mu.mem_map(STACK_ADDRESS, STACK_SIZE)
    #    - 为退出地址映射一小块内存，防止 UC_ERR_FETCH_UNMAPPED
    mu.mem_map(EXIT_ADDRESS, 4 * 1024)

    # 3. 写入数据和代码
    #    - 写入机器码到代码区
    mu.mem_write(CODE_ADDRESS, SUM_ARRAY_CODE)
    #    - 将输入数组转换为64位有符号整数的字节流并写入数据区
    array_bytes = b''.join(item.to_bytes(8, 'little', signed=True) for item in INPUT_ARRAY)
    mu.mem_write(ARRAY_ADDRESS, array_bytes)
    #    - 将退出地址写入堆栈，作为ret的返回地址
    mu.mem_write(STACK_ADDRESS + STACK_SIZE - 8, EXIT_ADDRESS.to_bytes(8, 'little'))

    # 4. 初始化寄存器状态
    #    - 设置堆栈指针 (RSP) 指向堆栈的顶部 (高地址)
    mu.reg_write(UC_X86_REG_RSP, STACK_ADDRESS + STACK_SIZE - 8)
    #    - 设置函数参数 (遵从 System V AMD64 ABI):
    #      - 第一个参数 (long* arr) 存入 RDI
    mu.reg_write(UC_X86_REG_RDI, ARRAY_ADDRESS)
    #      - 第二个参数 (int count) 存入 RSI
    mu.reg_write(UC_X86_REG_RSI, ARRAY_COUNT)
    
    #    - 为了调试，可以给其他寄存器设置一个已知初始值
    mu.reg_write(UC_X86_REG_RAX, 0)
    mu.reg_write(UC_X86_REG_RCX, 0)
    mu.reg_write(UC_X86_REG_RDX, 0)

    print("--- Starting Emulation ---")
    print(f"Input Array: {INPUT_ARRAY}")
    print(f"Expected Sum: {sum(INPUT_ARRAY)}")
    print("Initial register state (arguments):")
    print(f"RDI (arr ptr): 0x{ARRAY_ADDRESS:x}")
    print(f"RSI (count):   {ARRAY_COUNT}")
    print("-" * 26)

    # 5. 设置钩子并开始模拟
    #    - 添加一个代码钩子，在即将执行到我们设置的 "假" 返回地址时停止模拟
    def stop_on_exit(uc, address, size, user_data):
        if address == EXIT_ADDRESS:
            uc.emu_stop()

    mu.hook_add(UC_HOOK_CODE, stop_on_exit)
    
    # 6. 开始模拟执行
    #    - 从代码的起始地址开始
    #    - 由于我们有钩子来处理ret，所以不需要设置结束地址
    mu.emu_start(CODE_ADDRESS, 0) # 0 for 'until' means emulate until stop or error

    print("\n--- Emulation Finished ---")
    
    # 7. 获取并打印结果
    final_sum = mu.reg_read(UC_X86_REG_RAX)
    print(f"\nResult from RAX: {final_sum} (0x{final_sum:x})")

    print_registers(mu)

except UcError as e:
    print(f"ERROR: {e}")
    sys.exit(1) 