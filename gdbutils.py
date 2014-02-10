import gdb
import re
import codecs
import sys

stdout = codecs.getwriter("utf-8")(sys.stdout)

type_cache = {}
saved_null = False

def newval(typestr, val):
    return gdb.Value(val).cast(typ(typestr))

def typ(typestr):
    global type_cache
    if typestr in type_cache:
        return type_cache[typestr]

    m = re.match(r"^(\S*)\s*\*$", typestr)
    if m is None:
        typ = gdb.lookup_type(typestr)
    else:
        typ = gdb.lookup_type(m.group(1)).pointer()

    type_cache[typestr] = typ
    return typ

def parse_ptr(val, t):
    m = re.match('0[xX][0-9a-fA-F]+', val)
    if m:
        return newval(t, int(val, 16))
    return gdb.parse_and_eval(val)

def err(s):
    gdb.write("ERROR: %s\n" % str(s), gdb.STDERR)

def warn(s):
    gdb.write("WARNING: %s\n" % str(s), gdb.STDERR)

def out(s):
    stdout.write(s)

def ptr2int(ptr):
    return int(ptr.cast(typ("uintptr_t")))

def null():
    global saved_null
    if saved_null:
        return saved_null
    saved_null = newval("void*", 0)
    return saved_null

def globalvar(name):
    return gdb.lookup_global_symbol(name).value()

