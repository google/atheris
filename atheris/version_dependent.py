"""
This module manages the different aspects of bytecode instrumentation that
depend on specific python versions:
    - Instructions
    - Shape of a code object
    
Currently supported python versions are:
    - 3.6
    - 3.7
    - 3.8
    - 3.9
"""

import sys
import types

PYTHON_VERSION = sys.version_info[:2]

if PYTHON_VERSION < (3,6) or PYTHON_VERSION > (3,9):
    raise RuntimeError(f"You are fuzzing on an unsupported python version: {PYTHON_VERSION[0]}.{PYTHON_VERSION[1]}. Only 3.6 - 3.9 are supported.")

### Instruction categories ###

CONDITIONAL_JUMPS = [
    # common
    "FOR_ITER",
    "JUMP_IF_FALSE_OR_POP", 
    "JUMP_IF_TRUE_OR_POP",
    "POP_JUMP_IF_FALSE", 
    "POP_JUMP_IF_TRUE",
    
    # 3.9
    "JUMP_IF_NOT_EXC_MATCH",
]

UNCONDITIONAL_JUMPS = [
    # common
    "JUMP_FORWARD", 
    "JUMP_ABSOLUTE", 
    
    # 3.6 / 3.7
    "CONTINUE_LOOP",
    
    # 3.8
    "CALL_FINALLY", 
]

ENDS_FUNCTION = [
    # common
    "RAISE_VARARGS",
    "RETURN_VALUE",
    
    # 3.9
    "RERAISE",
]

HAVE_REL_REFERENCE = [
    # common
    "SETUP_WITH",
    "JUMP_FORWARD",
    "FOR_ITER",
    "SETUP_FINALLY",
    "CALL_FINALLY",
    
    # 3.6 / 3.7
    "SETUP_LOOP",
    "SETUP_EXCEPT",
]

HAVE_ABS_REFERENCE = [
    # common
    "POP_JUMP_IF_TRUE",
    "POP_JUMP_IF_FALSE",
    "JUMP_IF_TRUE_OR_POP",
    "JUMP_IF_FALSE_OR_POP",
    "JUMP_ABSOLUTE",
    
    # 3.6 / 3.7
    "CONTINUE_LOOP",
    
    # 3.9
    "JUMP_IF_NOT_EXC_MATCH",
]

### Compare ops ###

REVERSE_CMP_OP = [
    4,
    5,
    2,
    3,
    0,
    1
]

### CodeTypes ###

if (3,6) <= PYTHON_VERSION <= (3,7):
    def get_code_object(code_obj, stacksize, bytecode, consts, names, lnotab):
        return types.CodeType(
            code_obj.co_argcount,
            code_obj.co_kwonlyargcount,
            code_obj.co_nlocals,
            stacksize,
            code_obj.co_flags,
            bytecode,
            consts,
            names,
            code_obj.co_varnames,
            code_obj.co_filename,
            code_obj.co_name,
            code_obj.co_firstlineno,
            lnotab,
            code_obj.co_freevars,
            code_obj.co_cellvars
        )
    
else:
    def get_code_object(code_obj, stacksize, bytecode, consts, names, lnotab):
        return types.CodeType(
            code_obj.co_argcount,
            code_obj.co_posonlyargcount,
            code_obj.co_kwonlyargcount,
            code_obj.co_nlocals,
            stacksize,
            code_obj.co_flags,
            bytecode,
            consts,
            names,
            code_obj.co_varnames,
            code_obj.co_filename,
            code_obj.co_name,
            code_obj.co_firstlineno,
            lnotab,
            code_obj.co_freevars,
            code_obj.co_cellvars
        )
