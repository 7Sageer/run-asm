import re
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KsError, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT

# 假设我们将要把代码加载到内存地址 0x10000
BASE_ADDRESS = 0x10000

# ----------------------------------------------------
# 从 sum.s 中提取的 `sum_array` 函数核心汇编代码
# 这是标准的 AT&T 语法，由 GCC 生成
# ----------------------------------------------------
with open('sum.s', 'r') as f:
    ASM_CODE = f.read()

def clean_asm(code):
    """清理汇编代码，移除注释、空行和不必要的汇编器指令，返回一个干净的指令字符串"""
    lines = []
    # 移除的GCC汇编指令
    directives_to_remove = ('.file', '.ident', '.size', '.section', '.globl', '.type', '.text')
    
    for line in code.strip().split('\n'):
        # 移除行尾注释 (GAS 使用 #)
        line = line.split('#')[0].strip()

        if not line:
            continue
            
        # 过滤掉不需要的汇编指令
        if not line.startswith(directives_to_remove):
            lines.append(line)
            
    # 将所有行合并成一个单一的字符串，用换行符分隔
    # Keystone可以一次性处理包含多条指令和标签的字符串
    return "\n".join(lines)

# ----------------------------------------------------
# 主要工作流
# ----------------------------------------------------
cleaned_asm = clean_asm(ASM_CODE)

# 初始化 Keystone
ks = Ks(KS_ARCH_X86, KS_MODE_64)

# 关键修正: 明确告诉 Keystone 使用 AT&T 语法
# GCC 生成的汇编代码使用 AT&T 语法，而 Keystone 默认使用 NASM/Intel 语法
# 如果不设置此选项，Keystone 会无法解析 AT&T 语法的操作数 (e.g., %rax, $0)
ks.syntax = KS_OPT_SYNTAX_ATT

print("--- Assembling Code using Keystone (with AT&T Syntax) ---")

try:
    # Keystone 能够在其内部处理同一次汇编调用中的向前或向后引用的标签
    # 这极大地简化了自定义汇编器的编写过程
    encoding, count = ks.asm(cleaned_asm, BASE_ADDRESS)
    
    print(f"成功汇编 {count} 条指令。")
    print(f"函数 'sum_array' 的机器码 (从地址 {hex(BASE_ADDRESS)} 开始):")
    
    # 格式化输出
    hex_code = ' '.join(f'{b:02x}' for b in encoding)
    print(hex_code.upper())
    
    with open('sum.bin', 'wb') as f:
        f.write(bytes(encoding))

except KsError as e:
    print(f"汇编失败: {e}")
    print("\n错误排查提示:")
    print("1. 检查汇编代码是否存在语法错误。")
    print("2. 确认 Keystone 的架构、模式和语法设置是否与汇编代码匹配。")
    print("3. 对于复杂的代码，可能需要手动处理符号解析，但对于此示例，Keystone应能胜任。") 