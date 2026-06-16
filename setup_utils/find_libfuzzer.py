#!/usr/bin/env python3
import os
import sys
import platform
import subprocess

def find_libfuzzer():
    """This function returns either None or path to libfuzzer.
it may also interact with stderr"""
    uname = platform.system()

    libpaths = []
    if uname == "Darwin":
        libpaths.append("lib/darwin/libclang_rt.fuzzer_no_main_osx.a")
    elif uname == "Linux":
        machine = platform.machine()
        if machine == "x86_64":
            libpaths.append("lib/linux/libclang_rt.fuzzer_no_main-x86_64.a")
        elif machine == "i386":
            libpaths.append("lib/linux/libclang_rt.fuzzer_no_main-i386.a")
        elif machine == "i686":
            libpaths.append("lib/linux/libclang_rt.fuzzer_no_main-i386.a")
        elif machine == "aarch64":
            libpaths.append("lib/linux/libclang_rt.fuzzer_no_main-aarch64.a")
        else:
            sys.stderr.write(f"Failed to identify platform machine (got {machine}); set $LIBFUZZER_LIB to point directly to your libfuzzer .a file if the build fails.\n")
        libpaths.append("lib/*linux*/libclang_rt.fuzzer_no_main*.a")
    else:
        sys.stderr.write(f"Failed to identify platform (got {uname}); set $LIBFUZZER_LIB to point directly to your libfuzzer .a file if the build fails.\n")
    libpaths.append("lib/*/libclang_rt.fuzzer_no_main*.a")

    clang_bin = os.environ.get("CLANG_BIN", "clang")
    try:
        output = subprocess.check_output([clang_bin, "-print-search-dirs"], text=True, stderr=subprocess.DEVNULL)
    except:
        return

    search_dirs = []
    for line in output.splitlines():
        if line.startswith("libraries: ="):
            dirs = line[len("libraries: ="):].strip()
            if dirs:
                search_dirs = dirs.split(":")
            break

    if len(search_dirs) == 0:
        sys.stderr.write("Failed to get search paths from clang, set $LIBFUZZER_LIB to point directly to your libfuzzer .a file.")
        return

    for libpath in libpaths:
        for directory in search_dirs:
            candidate = os.path.join(directory, libpath)
            if os.path.isfile(candidate):
                # FOUND!
                return candidate

    sys.stderr.write(f"Failed to find libFuzzer archive in search path {':'.join(search_dirs)}\n")