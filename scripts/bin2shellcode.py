
import sys

def gen_code(shellcode, offset):
    code = ""
    code += '#include<stdio.h>\n'
    code += '#include<string.h>\n'
    code += 'unsigned char code[] = "%s";\n' % (shellcode)
    code += 'int main()\n'
    code += '{\n'
    code += '    printf("Shellcode Length: %d\\n", strlen(code));\n'
    code += '    int (*ret)() = (int(*)())(&code[%s]);\n' % (offset)
    code += '    ret();\n'
    code += '}\n'
    return code

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        with open(sys.argv[1], 'rb') as f:
            contents = f.read()
            out = ""
            for b in contents:
                out += "\\x" + hex(b)[2:]
            
            if len(sys.argv) == 3:
                code = gen_code(out, sys.argv[2])
            else:
                code = gen_code(out, 0)

            print(code)
