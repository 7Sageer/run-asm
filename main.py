import json
import re
import math
from compiler import compile_c_to_asm, assemble
from emulator import Emulator

def parse_c_args(args_str):
    """Parses a C-style argument string, respecting parentheses, brackets, and braces."""
    if not args_str:
        return []

    args = []
    current_arg = ''
    paren_level = 0
    bracket_level = 0
    brace_level = 0
    
    for char in args_str:
        if char == '(': paren_level += 1
        elif char == ')': paren_level -= 1
        elif char == '[': bracket_level += 1
        elif char == ']': bracket_level -= 1
        elif char == '{': brace_level += 1
        elif char == '}': brace_level -= 1
        
        if char == ',' and paren_level == 0 and bracket_level == 0 and brace_level == 0:
            args.append(current_arg.strip())
            current_arg = ''
        else:
            current_arg += char
            
    if current_arg:
        args.append(current_arg.strip())
        
    return [arg for arg in args if arg]

def parse_signature(c_func):
    """Parses a C function string to extract its name, return type, and argument types."""
    # A more robust regex to handle multi-word types like 'long long'
    match = re.search(r'([\w\s\*]+?)\s*(\w+)\s*\((.*?)\)', c_func, re.DOTALL)
    if not match:
        raise ValueError("Could not parse function signature.")
    
    return_type, name, args_str = match.groups()
    
    # Clean and normalize the return type
    clean_return_type = return_type.strip().replace("const", "").strip()
    if 'long long' in clean_return_type:
        final_return_type = 'long'
    elif 'long' in clean_return_type:
        final_return_type = 'long'
    else:
        # Take the first word, remove pointer stuff for a clean type
        final_return_type = clean_return_type.replace('*','').strip().split()[0]
    
    # Add back pointer if it exists
    if '*' in clean_return_type or '[]' in clean_return_type:
        # Avoid double-star
        if not final_return_type.endswith('*'):
            final_return_type += '*'

    if not args_str or args_str.strip() == 'void':
        arg_types = []
    else:
        arg_types = []
        for arg in parse_c_args(args_str):
            clean_arg = arg.strip().replace('const', '').strip()
            
            is_pointer = '*' in clean_arg or '[]' in clean_arg
            
            base_type_str = clean_arg.replace('*', '').replace('[]', '').strip()
            
            type_words = base_type_str.split(' ')
            base_type = type_words[0]
            
            if base_type == 'long' and len(type_words) > 1 and type_words[1] == 'long':
                base_type = 'long'

            if is_pointer:
                arg_types.append(f'{base_type}*')
            else:
                arg_types.append(base_type)

    return {'name': name, 'return_type': final_return_type, 'arg_types': arg_types}

def parse_tests(c_test):
    """Parses C test code to extract variable definitions and assert statements."""
    # Simple regex to find array initializations (int, float, long, double, char)
    array_defs = re.findall(r'(?:int|float|long|double|char)\s*(\w+\[\])\s*=\s*\{(.*?)\};', c_test)
    variables = {}
    for name, values_str in array_defs:
        name = name.replace('[]', '')
        # Convert string values to numbers
        if values_str:
            values = [float(v) if '.' in v else int(v) for v in values_str.split(',')]
        else:
            values = []
        variables[name] = values
        
    # Regex to find individual assertions
    # Handles func(...) == expected, func(...) and fabs(func(...) - expected) < tolerance
    asserts = re.findall(r'assert\((.*?)\);', c_test)
    
    tests = []
    for assertion in asserts:
        assertion = assertion.strip()
        # Case 1: fabs(func(...) - expected) < tolerance
        match = re.search(r'fabs\(\s*func\d+\((.*?)\)\s*-\s*(.*?)\)\s*<\s*[\d.e-]+', assertion)
        if match:
            args_str, expected_str = match.groups()
            try:
                expected = eval(expected_str)
            except:
                expected = float(expected_str.replace('f', ''))
        else:
            # Case 2: func(...) == expected
            match = re.search(r'func\d+\((.*?)\)\s*==\s*(.*)', assertion)
            if match:
                args_str, expected_str = match.groups()
                expected_str = expected_str.strip()
                if not expected_str: expected_str = '0' # Default to 0 if empty
                if expected_str == 'true':
                    expected = 1
                elif expected_str == 'false':
                    expected = 0
                else:
                    try:
                        expected = float(expected_str.replace('f', '')) if '.' in expected_str or 'f' in expected_str else int(expected_str)
                    except ValueError:
                        # Handle special cases like (0.3) -> 0.3
                        expected = float(expected_str.strip('()'))

            else:
                 # Case 3: func(...) (implicitly checking for non-zero)
                match = re.search(r'func\d+\((.*?)\)', assertion)
                if not match: continue
                args_str = match.group(1)
                expected = 1 # assume true

        args = parse_c_args(args_str)
        # Resolve variable names to their values
        resolved_args = []
        for arg in args:
            if arg in variables:
                resolved_args.append(variables[arg])
            else:
                try:
                    # Convert literal values, removing 'f' from floats
                    if arg: # Ensure arg is not an empty string
                        resolved_args.append(float(arg.replace('f','')) if '.' in arg or 'f' in arg else int(arg))
                except ValueError:
                    # if it is a var name like "size" which is not pre-defined
                    # we can not handle it now.
                    pass
        tests.append({'args': resolved_args, 'expected': expected})
    return tests


def main():
    """Main function to run the entire toolchain."""
    try:
        with open('humaneval-c-all.json', 'r') as f:
            problems = json.load(f)
    except FileNotFoundError:
        print("Error: 'humaneval-c-no-syscall.json' not found. Make sure you are running from the project root.")
        return

    # Process only the first optimization level for each unique task ID
    processed_tasks = set()
    successful_tests = 0
    total_tests = 0
    
    # Program statistics
    total_programs = len(problems)
    unique_programs = 0
    optimization_counts = {"O0": 0, "O1": 0, "O2": 0, "O3": 0}
    successful_compilations = 0
    successful_assemblies = 0
    
    for problem in problems:
        task_id = problem['task_id']
        opt_level = problem['type']  # O0, O1, etc.
        
        # Count optimization levels
        if opt_level in optimization_counts:
            optimization_counts[opt_level] += 1
        
        if task_id in processed_tasks:
            continue
        
        unique_programs += 1
        processed_tasks.add(task_id)

        c_func = problem['c_func'].replace('func0', f'func{task_id}')
        c_test = problem['c_test'].replace('func0', f'func{task_id}')
        
        print(f"\n--- Processing Task ID: {task_id}, Opt: {opt_level} ---")
        
        try:
            signature = parse_signature(c_func)
            tests = parse_tests(c_test)
        except (ValueError, IndexError) as e:
            print(f"Failed to parse C code for task {task_id}: {e}")
            continue

        asm_code = compile_c_to_asm(c_func, optimization=opt_level)
        if not asm_code:
            continue
        
        successful_compilations += 1
            
        machine_code = assemble(asm_code)
        if machine_code is None:
            continue
        
        successful_assemblies += 1

        for i, test in enumerate(tests):
            total_tests += 1
            print(f"\n- Running Test Case #{i+1}")
            print(f"  Arguments: {test['args']}")
            print(f"  Expected: {test['expected']}")

            emulator = Emulator()
            
            # Make sure the arguments match the function signature
            args_to_use = list(test['args'])  # Convert to list in case we need to modify it
            while len(args_to_use) < len(signature['arg_types']):
                # Add default values for missing arguments
                arg_type = signature['arg_types'][len(args_to_use)]
                if '*' in arg_type:  # For pointer types
                    args_to_use.append([])
                elif arg_type in ['float', 'double']:
                    args_to_use.append(0.0)
                else:  # For integer types
                    args_to_use.append(0)
            
            # Ensure that arguments for pointer types are lists/tuples
            # This handles cases where a literal is passed for a pointer argument
            for i, arg_type in enumerate(signature['arg_types']):
                if i < len(args_to_use) and '*' in arg_type:
                    if not isinstance(args_to_use[i], (list, tuple)):
                        # It's a pointer type, but the argument is a literal.
                        # Wrap it in a list to be treated as a pointer to a single value.
                        args_to_use[i] = [args_to_use[i]]
            
            result = emulator.run(machine_code, signature, args_to_use)
            
            if result is None:
                print("  Emulation failed.")
                continue

            print(f"  Actual: {result}")

            # Comparison logic with tolerance for floats
            if isinstance(test['expected'], float):
                if math.isclose(result, test['expected'], rel_tol=1e-5, abs_tol=1e-5):
                    print("  Result: PASSED")
                    successful_tests += 1
                else:
                    print("  Result: FAILED")
            else:
                if result == test['expected']:
                    print("  Result: PASSED")
                    successful_tests += 1
                else:
                    print("  Result: FAILED")

    print("\n--- Program Statistics ---")
    print(f"Total programs: {total_programs}")
    print(f"Unique programs: {unique_programs}")
    print(f"Programs by optimization level:")
    for opt, count in optimization_counts.items():
        print(f"  {opt}: {count}")
    print(f"Successful compilations: {successful_compilations}")
    print(f"Successful assemblies: {successful_assemblies}")
    
    print("\n--- Test Statistics ---")
    print(f"Total tests run: {total_tests}")
    print(f"Successful tests: {successful_tests}")
    if total_tests > 0:
        success_rate = (successful_tests / total_tests) * 100
        print(f"Success rate: {success_rate:.2f}%")


if __name__ == '__main__':
    main() 