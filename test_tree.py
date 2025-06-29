from tree_sitter import Language, Parser
import pathlib, re

# 1. Build once (≈30 s).  After that use the .so file.
# Language.build_library('build/my-languages.so',
#     ['tree-sitter-c', 'tree-sitter-cpp'])

LIB = 'build/my-languages.so'
C_LANG = Language(LIB, 'c')

parser = Parser()
parser.set_language(C_LANG)

code = b"""
char buf[10];
strcpy(buf, src);           // unsafe
if (i < sizeof(buf)) strcpy(buf, src);  // safe
"""



def walk(node, tokens,code):
    if node.type == 'call_expression':
        func_name = code[node.child_by_field_name('function').start_byte:
                        node.child_by_field_name('function').end_byte].decode()
        tokens.append(f"CALL_{func_name}")
    elif node.type == 'identifier':
        ident = code[node.start_byte:node.end_byte].decode()
        if ident not in KEYWORDS:
            tokens.append("IDENT")
        else:
            tokens.append(ident.upper())
    for child in node.children:
        walk(child, tokens,code)

tree = parser.parse(code)
root = tree.root_node
KEYWORDS = {...}  # your reserved-word set
tok_seq = []
walk(root, tok_seq,code)
print(tok_seq)
# -> ['IDENT', 'CALL_strcpy', 'IDENT', 'IDENT', 'IF', 'CALL_strcpy']

