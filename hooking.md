# This file explains how Atheris hooks and instruments Python code

There are 2 main different ways that Atheris hooks Python code.


### 1) Overwriting Python functions

The first way is by overwriting Python functions so that the new function
first calls the hook before calling the original function. The Regex hooking in
`function_hooks.py` uses this strategy. If possible, use this strategy for
simplicity.


### 2) Instrumenting Bytecode

The second, more complicated way is by rewriting the Python bytecode.
The branch hooking, compare operation hooking, and str method
hooking in `instrument_bytecode.py` all use this strategy.
In `instrument_bytecode.py`, there is a function that essentially looks for a
specific Python bytecode instruction and then inserts the hook, which is
just a new sequence of bytecode instructions.
However, the branch hooking and compare op hooking differ from the
str method hooking. The branch hooking and compare op hooking add instructions
that call native C++ code directly. However, the str hooking adds instructions
that call a proxy Python function which then calls the native C++ code. The
reason that str hooking uses this proxy is because some preprocessing has to
occur before we can call the native code. Namely, in the Python proxy we need
to typecheck the caller of the str method, and we need to check that the
correct arguments are passed in to the function call before we can call the
native code.


## Generalizing the str hooking to hooking arbitrary methods

For certain methods/functions such as the str `startswith` and `endswith`
methods, Python blocks us from overwriting them and using strategy #1, so
we have to instrument the bytecode instead, which is what str hooking does.

If there is another such method or function that needs to be hooked, we can
follow the pattern used for str hooking. Use a similar structure to the
`trace_str_flow` method in `instrument_bytecode.py`, replacing the call to
`_is_str_hookable` with a similar method that does the appropriate check. In
`patch_code`, call this new method. In `trace_str_flow`, also replace
`generate_hook_str_invocation` with another method that generates a function
call to the new proxy function. This new proxy function should be defined in
`function_hooks.py`, following a similar structure to `_hook_str`. Finally, add
the new hook name to the `EnabledHooks` class.
