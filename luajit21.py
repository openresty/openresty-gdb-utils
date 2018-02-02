import sys

import gdb
import gdbutils
import ngxlua
import re
import time

typ = gdbutils.typ
null = gdbutils.null
newval = gdbutils.newval
ptr2int = gdbutils.ptr2int
err = gdbutils.err
out = gdbutils.out
warn = gdbutils.warn

if sys.version_info[0] >= 3:  # Python 3K
    global xrange
    xrange = range

def LJ_TNIL():
    return ~newval("unsigned int", 0)

def LJ_TFALSE():
    return ~newval("unsigned int", 1)

def LJ_TTRUE():
    return ~newval("unsigned int", 2)

def LJ_TLIGHTUD():
    return ~newval("unsigned int", 3)

def LJ_TSTR():
    return ~newval("unsigned int", 4)

def LJ_TUPVAL():
    return ~newval("unsigned int", 5)

def LJ_TTHREAD():
    return ~newval("unsigned int", 6)

def LJ_TPROTO():
    return ~newval("unsigned int", 7)

def LJ_TFUNC():
    return ~newval("unsigned int", 8)

def LJ_TTRACE():
    return ~newval("unsigned int", 9)

def LJ_TCDATA():
    return ~newval("unsigned int", 10)

def LJ_TTAB():
    return ~newval("unsigned int", 11)

def LJ_TUDATA():
    return ~newval("unsigned int", 12)

def LJ_TNUMX():
    return ~newval("unsigned int", 13)

def LJ_TISNUM():
    return newval("unsigned int", 0xfffeffff)

def LJ_TISGCV():
    return newval("unsigned int", 1 + ~4)

BC_RETM = 73
BC_RET = 74
BC_RET0 = 75
BC_RET1 = 76

FRAME_LUA = 0
FRAME_C = 1
FRAME_CONT = 2
FRAME_VARG = 3

FRAME_TYPE = 3
FRAME_P = 4
FRAME_TYPEP = FRAME_TYPE | FRAME_P

CFRAME_RESUME = 1
CFRAME_UNWIND_FF = 2
CFRAME_RAWMASK = ~(CFRAME_RESUME|CFRAME_UNWIND_FF)
CFRAME_OFS_L = 416
CFRAME_OFS_PC = 7*4  # for x86_64 (non-windows)

cfunc_cache = {}

LJ_VMST_INTERP = 0
LJ_VMST_C = 1
LJ_VMST_GC = 2
LJ_VMST_EXIT = 3
LJ_VMST_RECORD = 4
LJ_VMST_OPT = 5
LJ_VMST_ASM = 6
LJ_VMST__MAX = 7

vmstates = ['Interpreted', 'C code (from interpreted Lua code)', \
        'Garbage collector', 'Trace exit handler', \
        'Trace recorder', 'Optimizer', 'Assembler']

NO_BCPOS = ~0

FF_LUA = 0
FF_C   = 1

GCROOT_MAX = 38

def get_global_L():
    gL, _ = gdb.lookup_symbol("globalL")
    if gL:
        return gL.value()

    cycle = gdb.lookup_global_symbol("ngx_cycle")
    if cycle:
        cycle = cycle.value()
        gL = ngxlua.ngx_lua_get_main_lua_vm(cycle)
        if gL:
            return gL

    raise gdb.GdbError("No global L located (tried globalL and ngx_cycle)")

def get_cur_L():
    mL = get_global_L()
    #out("mL type: %s\n" % str(mL.type))
    #out("null type: %s\n" % str(null().type))
    if mL == null():
        return mL
    return gcref(G(mL)['cur_L'])['th'].address

def gcval(o):
    return gcref(o['gcr'])

def tabV(o):
    return gcval(o)['tab'].address

def cframe_pc(cf):
    #print("CFRAME!!")
    return mref((cf.cast(typ("char*")) + CFRAME_OFS_PC).cast(typ("MRef*")).dereference(), \
                "BCIns")

def cframe_L(cf):
    return gcref((cf.cast(typ("char*")) + CFRAME_OFS_L) \
            .cast(typ("GCRef*")).dereference())['th'].address

def frame_ftsz(tv):
    return tv['fr']['tp']['ftsz']

def frame_type(f):
    return (frame_ftsz(f) & FRAME_TYPE)

def frame_islua(f):
    return frame_type(f) == FRAME_LUA

def frame_typep(f):
    return (frame_ftsz(f) & FRAME_TYPEP)

def frame_isvarg(f):
    return frame_typep(f) == FRAME_VARG

def frame_iscont(f):
    return frame_typep(f) == FRAME_CONT

def sizeof(typ):
    return gdb.parse_and_eval("sizeof(" + typ + ")")

def gcref(r):
    return r['gcptr32'].cast(typ("uintptr_t")).cast(typ("GCobj*"))

def gcrefp(r, t):
    #((t *)(void *)(uintptr_t)(r).gcptr32)
    return r['gcptr32'].cast(typ(t + "*"))

def frame_gc(frame):
    return gcref(frame['fr']['func'])

def obj2gco(v):
    return v.cast(typ("GCobj*"))

def mref(r, t):
    return r['ptr32'].cast(typ("uintptr_t")).cast(typ(t + "*"))

def frame_pc(f):
    return mref(f['fr']['tp']['pcr'], "BCIns")

def frame_contpc(f):
    return frame_pc(f - 1)

def bc_a(i):
    return newval("BCReg", (i >> 8) & 0xff)

def frame_prevl(f):
    return f - (1 + bc_a(frame_pc(f)[-1]))

def frame_sized(f):
    return (frame_ftsz(f) & ~FRAME_TYPEP)

def frame_prevd(f):
    #print "f = %x, sized = %x" % (ptr2int(f.cast(typ("char*"))), frame_sized(f))
    return (f.cast(typ("char*")) - frame_sized(f)).cast(typ("TValue*"))

def frame_prev(f):
    if frame_islua(f):
        return frame_prevl(f)
    else:
        return frame_prevd(f)

def tvref(r):
    return mref(r, "TValue")

def lj_debug_frame(L, base, level, bot):
    frame = base - 1
    nextframe = frame
    while frame > bot:
        #print "checking level %d\n" % level
        if frame_gc(frame) == obj2gco(L):
            level += 1

        if level == 0:
            return (frame, nextframe - frame)

        level -= 1
        nextframe = frame
        if frame_islua(frame):
            frame = frame_prevl(frame)
        else:
            if frame_isvarg(frame):
                level += 1
            frame = frame_prevd(frame)
    return (null(), level)

def frame_func(f):
    return frame_gc(f)['fn'].address

def isluafunc(fn):
    return fn['c']['ffid'] == FF_LUA

def isffunc(fn):
    return fn['c']['ffid'] > FF_C

def funcproto(fn):
    return (mref(fn['l']['pc'], "char") - typ("GCproto").sizeof) \
            .cast(typ("GCproto*"))

def proto_bc(pt):
    return (pt.cast(typ("char*")) + typ("GCproto").sizeof).cast(typ("BCIns*"))

def proto_bcpos(pt, pc):
    return (pc - proto_bc(pt)).cast(typ("BCPos"))

def proto_lineinfo(pt):
    return mref(pt['lineinfo'], "void")

def lj_debug_line(pt, pc):
    lineinfo = proto_lineinfo(pt)
    if pc <= pt['sizebc'] and lineinfo:
        first = pt['firstline']
        if pc == pt['sizebc']:
            return first + pt['numline']
        if pc == 0:
            return first
        pc -= 1
        if pt['numline'] < 256:
            return first + lineinfo.cast(typ("uint8_t*"))[pc].cast(typ("BCLine"))
        elif pt['numline'] < 65536:
            return first + lineinfo.cast(typ("uint16_t*"))[pc].cast(typ("BCLine"))
        else:
            return first + lineinfo.cast(typ("uint32_t*"))[pc].cast(typ("BCLine"))
    #print "Nothing: ", str(lineinfo)
    return 0

def debug_framepc(L, T, fn, pt, nextframe):
    if not isluafunc(fn):
        return NO_BCPOS
    if not nextframe:
        cf = cframe_raw(L['cframe'])
        #print("cf 0x%x" % ptr2int(cf))
        if not cf or cframe_pc(cf) == cframe_L(cf):
            return NO_BCPOS
        ins = cframe_pc(cf)
        #print("cframe pc: [0x%x]" % ptr2int(ins))
    else:
        if frame_islua(nextframe):
            #print("frame pc")
            ins = frame_pc(nextframe)
        elif frame_iscont(nextframe):
            #print("frame contpc")
            ins = frame_contpc(nextframe)
        else:
            warn("Lua function below errfunc/gc/hook not supported yet")
            return NO_BCPOS
    pos = proto_bcpos(pt, ins) - 1
    if pos > pt['sizebc']:
        T = ((ins - 1).cast(typ("char*")) - \
                typ("GCtrace")['startins'].bitpos / 8).cast(typ("GCtrace*"))
        #print("T: %d" % int(T['traceno']))
        try:
            pos = proto_bcpos(pt, mref(T['startpc'], "BCIns"))
        except:
            return NO_BCPOS
    return pos

def debug_frameline(L, T, fn, pt, nextframe):
    pc = debug_framepc(L, T, fn, pt, nextframe)
    if pc != NO_BCPOS:
        pt = funcproto(fn)
        return lj_debug_line(pt, pc)
    #print("pc == %d" % pc)
    return -1

def strref(r):
    return gcref(r)['str'].address

def tabref(r):
    return gcref(r)['tab'].address

def proto_chunkname(pt):
    return strref(pt['chunkname'])

def strdata(s):
    return (s + 1).cast(typ("char*"))

def G(L):
    return mref(L['glref'], "global_State")

def cframe_raw(cf):
    return (cf.cast(typ("intptr_t")) & CFRAME_RAWMASK).cast(typ("void*"))

def proto_varinfo(pt):
    return mref(pt['varinfo'], 'uint8_t')

def lua_gettop(L):
    return int(L['top'] - L['base'])

def stkindex2adr(L, idx):
    """
    Given L and a stack index, returns the corresponding TValue object.
    Does not work on pseudo-indexes!
    """
    if idx > 0:
        o = L['base'] + (idx - 1)
        return o if o <= L['top'] else None
    else:
        # negative index
        assert idx != 0
        assert -idx <= L['top'] - L['base']
        return L['top'] + idx

VARNAME_END = 0
VARNAME__MAX = 7

def lj_buf_ruleb128(p):
    v = p.dereference().cast(typ("uint32_t"))
    p += 1
    if v >= 0x80:
        sh = 0
        v = v & 0x7f
        while True:
            sh += 7
            v = v | ((p.dereference() & 0x7f) << sh)
            if p.dereference() < 0x80:
                p += 1
                break
            p += 1
    return v, p

builtin_variable_names = [ \
        "(for index)", \
        "(for limit)", \
        "(for step)", \
        "(for generator)", \
        "(for state)", \
        "(for control)"]

def debug_varname(pt, pc, slot):
    p = proto_varinfo(pt).cast(typ("char*"))
    if p:
        lastpc = 0
        while True:
            name = p
            vn = p.cast(typ("uint8_t*")).dereference().cast(typ("uint32_t"))
            if vn < VARNAME__MAX:
                if vn == VARNAME_END:
                    break
            else:
                while True:
                    p += 1
                    if p.cast(typ("uint8_t*")).dereference() == 0:
                        break
            p += 1
            v, p = lj_buf_ruleb128(p)
            startpc = lastpc + v
            lastpc = startpc
            if startpc > pc:
                break
            v, p = lj_buf_ruleb128(p)
            endpc = startpc + v
            if pc < endpc and slot == 0:
                if vn < VARNAME__MAX:
                    out("\tlocal \"%s\"\n" % builtin_variable_names[int(vn - 1)])
                else:
                    out("\tlocal \"%s\":\n" % name.string('iso-8859-6', 'ignore'))
                return True
            slot = slot - 1
    return False

def lj_debug_dumpstack(L, T, depth, base, full):
    global cfunc_cache

    level = 0
    dir = 1
    if depth < 0:
        level = ~depth
        depth = dir = -1

    bot = tvref(L['stack'])
    while level != depth:
        #print "checking level: %d" % level

        bt = ""
        frame, size = lj_debug_frame(L, base, level, bot)

        if frame:
            nextframe = (frame + size) if size else null()
            fn = frame_func(frame)
            #print "type(fn) == %s" % fn.type
            if not fn:
                return

            pt = None

            if isluafunc(fn):
                pt = funcproto(fn)
                line = debug_frameline(L, T, fn, pt, nextframe)
                #print("line: %d\n" % line)
                if line <= 0:
                    #print str(pt.dereference)
                    line = int(pt['firstline'])
                name = proto_chunkname(pt)
                if not name:
                    return ""
                path = lstr2str(name)
                bt += "%s:%d\n" % (path, line)

            elif isffunc(fn):
                bt += "builtin#%d\n" % int(fn['c']['ffid'])

            else:
                cfunc = fn['c']['f']
                key = str(cfunc)
                if key in cfunc_cache:
                    sym = cfunc_cache[key]

                else:
                    sym = "C:%s\n" % cfunc
                    m = re.search('<.*?(\w+)*.*?>', cfunc.__str__())
                    if m:
                        sym = "C:%s\n" % m.group(1)
                    else:
                        sym = "C:%s\n" % key

                    cfunc_cache[key] = sym

                bt += sym
                #print "bt: " + sym

            out(bt)

            if full:
                if not pt:
                    pt = funcproto(fn)
                pc = debug_framepc(L, T, fn, pt, nextframe)
                if pc != NO_BCPOS:
                    nf = nextframe
                    if not nf:
                        nf = L['top']
                    for slot in xrange(1, int(nf - frame)):
                        tv = frame + slot
                        if debug_varname(pt, pc, slot - 1):
                            dump_tvalue(tv)

        elif dir == 1:
            break

        else:
            level -= size

        level += dir

    return bt

def G2GG(gl):
    #print(type(typ("GG_State")['g'].bitpos))
    diff = gl.cast(typ("char*")) - int(typ("GG_State")['g'].bitpos / 8)
    return diff.cast(typ("GG_State*"))

def G2J(gl):
    return G2GG(gl)['J'].address

def traceref(J, n):
    return gcref(J['trace'][n]).cast(typ("GCtrace*"))

class lbt(gdb.Command):
    """This command dumps out the current Lua-land backtrace in the lua_State specified. Only LuaJIT 2.1 is supported.
Usage: lbt [L]
       lbt full [L]"""

    def __init__ (self):
        super (lbt, self).__init__("lbt", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) > 2:
            raise gdb.GdbError("Usage: lbt [full] [L]")

        full = False

        if len(argv) > 0 and argv[0] == "full":
            full = True
            if len(argv) == 2:
                L = gdbutils.parse_ptr(argv[1], "lua_State*")
                if not L or str(L) == "void":
                    raise gdb.GdbError("L empty")
            else:
                L = get_cur_L()

        else:
            if len(argv) == 1:
                L = gdbutils.parse_ptr(argv[0], "lua_State*")
                if not L or str(L) == "void":
                    raise gdb.GdbError("L empty")
            else:
                L = get_cur_L()

        #print "g: ", hex(int(L['glref']['ptr32']))

        if L == null():
            raise gdb.GdbError("L is NULL")

        g = G(L)

        vmstate = int(g['vmstate'])
        #print "vmstate = %d" % vmstate

        if vmstate >= 0:
            #print "compiled code"
            traceno = vmstate
            J = G2J(g)
            T = traceref(J, traceno)
            base = tvref(g['jit_base'])
            if not base:
                try:
                    base = tvref(g['saved_jit_base'])
                except:
                    pass

            if not base:
                raise gdb.GdbError("jit base is NULL (trace #%d)" % int(T['traceno']))
            bt = lj_debug_dumpstack(L, T, 30, base, full)

        else:
            if vmstate == ~LJ_VMST_EXIT:
                base = tvref(g['jit_base'])
                if base:
                    bt = lj_debug_dumpstack(L, 0, 30, base, full)

                else:
                    base = L['base']
                    bt = lj_debug_dumpstack(L, 0, 30, base, full)

            else:
                if vmstate == ~LJ_VMST_INTERP and not L['cframe']:
                    out("No Lua code running.\n")
                    return

                if vmstate == ~LJ_VMST_INTERP or \
                       vmstate == ~LJ_VMST_C or \
                       vmstate == ~LJ_VMST_GC:
                    if vmstate == ~LJ_VMST_INTERP:
                        #out("Fetching edx...")
                        base = gdb.parse_and_eval("$edx").cast(typ("TValue*"))

                    else:
                        base = L['base']

                    bt = lj_debug_dumpstack(L, 0, 30, base, full)

                else:
                    out("No Lua code running.\n")
                    return

lbt()

class lvmst(gdb.Command):
    """This command prints out the current LuaJIT VM state in the lua_State specified.
Usage: lvmst [L]"""

    def __init__ (self):
        super (lvmst, self).__init__("lvmst", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) > 1:
            raise gdb.GdbError("Usage: lvmst [L]")

        if len(argv) == 1:
            L = gdbutils.parse_ptr(argv[0], "lua_State*")
            if not L or str(L) == "void":
                raise gdb.GdbError("L empty")
        else:
            L = get_cur_L()

        #print "g: ", hex(int(L['glref']['ptr32']))

        g = G(L)

        vmstate = int(g['vmstate'])
        if vmstate >= 0:
            out("Compiled Lua code (trace #%d)\n" % vmstate)

        elif ~vmstate >= LJ_VMST__MAX:
            raise gdb.GdbError("Invalid VM state: ", ~vmstate)

        elif ~vmstate == LJ_VMST_GC:
            out("current VM state: Garbage collector (")
            if tvref(g['jit_base']):
                out("from compiled Lua code)\n")
            else:
                out("from interpreter)\n")

        else:
            #print "vmstate = %d" % vmstate
            out("current VM state: %s\n" % vmstates[~vmstate])

lvmst()

class lmainL(gdb.Command):
    """This command prints out the main Lua thread's state
Usage: lmainL"""

    def __init__ (self):
        super (lmainL, self).__init__("lmainL", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) != 0:
            raise gdb.GdbError("Usage: lmainL")

        L = get_global_L()
        out("(lua_State*)0x%x\n" % ptr2int(L))

lmainL()

class lcurL(gdb.Command):
    """This command prints out the current running Lua thread's state
Usage: lcurL"""

    def __init__ (self):
        super (lcurL, self).__init__("lcurL", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) != 0:
            raise gdb.GdbError("Usage: lcurL")

        L = get_cur_L()
        out("(lua_State*)0x%x\n" % ptr2int(L))

lcurL()

class lglobtab(gdb.Command):
    """This command prints out the global environment table.
Usage: lglobtab [L]"""

    def __init__ (self):
        super (lglobtab, self).__init__("lglobtab", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) > 1:
            raise gdb.GdbError("Usage: lglobtab [L]")

        if len(argv) == 1:
            L = gdbutils.parse_ptr(argv[0], "lua_State*")
            if not L or str(L) == "void":
                raise gdb.GdbError("L empty")
        else:
            L = get_cur_L()

        #print "g: ", hex(int(L['glref']['ptr32']))

        out("(GCtab*)0x%x\n" % ptr2int(tabref(L['env'])))

lglobtab()

def noderef(r):
    return mref(r, "Node")

def itype(o):
    return o['it']

def tvisnil(o):
    return itype(o) == LJ_TNIL()

def tvisfunc(o):
    return itype(o) == LJ_TFUNC()

def tvistrue(o):
    return itype(o) == LJ_TTRUE()

def tvisfalse(o):
    return itype(o) == LJ_TFALSE()

def tvisstr(o):
    return itype(o) == LJ_TSTR()

def tvisnumber(o):
    return itype(o) <= LJ_TISNUM()

def tvisgcv(o):
    return (itype(o) - LJ_TISGCV()) > (LJ_TNUMX() - LJ_TISGCV())

def tvisint(o):
    return itype(o) == LJ_TISNUM()

def strV(o):
    return gcval(o)['str'].address

def lstr2str(gcs):
    kstr = strdata(gcs)
    if not kstr:
        return ""
    return kstr.string('iso-8859-6', 'ignore', int(gcs['len']))

def lj_tab_getstr(t, k):
    klen = len(k)
    hmask = int(t['hmask'])
    node = noderef(t['node'])
    for i in xrange(hmask + 1):
        nn = node[i]
        val = nn['val'].address
        if not tvisnil(val):
            key = nn['key'].address
            if tvisstr(key):
                gcs = strV(key)
                #print "Found a string key with len %d" % int(gcs['len'])
                if gcs['len'] == klen:
                    s = lstr2str(gcs)
                    if s == k:
                        return val
    return None

class ltabgets(gdb.Command):
    """This command prints out the specified field in the specified Lua table
Usage: ltabgets tab field"""

    def __init__ (self):
        super (ltabgets, self).__init__("ltabgets", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) != 2:
            raise gdb.GdbError("Usage: ltabgets tab field")

        m = re.match('0x[0-9a-fA-F]+', argv[0])
        if m:
            val = gdb.Value(int(argv[0], 16)).cast(typ("TValue*"))

        else:
            val = gdb.parse_and_eval(argv[0])

        if not val:
            raise gdb.GdbError("table argument empty")
            return

        typstr = str(val.type)
        if typstr == "GCtab *":
            tab = val

        else:
            tab = tabV(val)

        key = argv[1]

        tv = lj_tab_getstr(tab, key)
        if tv:
            out("(TValue*)%#x\n" % ptr2int(tv))
            dump_tvalue(tv)

        else:
            raise gdb.GdbError("Key \"%s\" not found." % key)

        #print "g: ", hex(int(L['glref']['ptr32']))

ltabgets()

def ltype(tv, t=None):
    if not t:
        t = tv['it']

    #print "t = %d, lightud: %d" % (t, LJ_TLIGHTUD())

    if t == LJ_TNIL():
        return "nil"

    if t == LJ_TSTR():
        return "string"

    if t == LJ_TFALSE():
        return "false"

    if t == LJ_TTRUE():
        return "true"

    if t == LJ_TLIGHTUD():
        return "lightuserdata"

    if t == LJ_TTHREAD():
        return "thread"

    if t == LJ_TUPVAL():
        return "upvalue"

    if t == LJ_TPROTO():
        return "proto"

    if t == LJ_TFUNC():
        return "function"

    if t == LJ_TTRACE():
        return "trace"

    if t == LJ_TCDATA():
        return "cdata"

    if t == LJ_TTAB():
        return "table"

    if t == LJ_TUDATA():
        return "userdata"

    if t == LJ_TNUMX():
        return "number"

    if t.cast(typ("int32_t")) >> 15 == -2:
        return "lightuserdata"

    return "number"

def tvisudata(o):
    return itype(o) == LJ_TUDATA()

def udataV(o):
    return gcval(o)['ud'].address

UDTYPE_USERDATA = 0
UDTYPE_IO_FILE = 1
UDTYPE_FFI_CLIB = 2
UDTYPE__MAX = 3

udata_types = ['userdata', 'io file', 'ffi clib']

def uddata(u):
    return (u + 1).cast(typ("void*"))

def tviscdata(o):
    return itype(o) == LJ_TCDATA()

def ctype_ctsG(g):
    return mref(g['ctype_state'], 'CTState')

def ctype_cts(L):
    return ctype_ctsG(G(L))

def cdataV(o):
    return gcval(o)['cd'].address

def ctype_get(cts, id):
    return cts['tab'][id].address

CTSHIFT_NUM = 28
CT_HASSIZE = 5
CT_ATTRIB = 8
CTMASK_CID = 0x0000ffff

def ctype_type(info):
    return info >> CTSHIFT_NUM

ctype_names = [ 'num', 'struct', 'ptr', 'array', \
        'void', 'enum', 'func', 'typedef', 'attribute', 'field', \
        'bitfield', 'constant value', 'extern', 'keyworkd']

def cdataptr(cd):
    return (cd + 1).cast(typ("void*"))

def tvislightud(o):
    t = itype(o)
    if t == LJ_TLIGHTUD():
        return True

    if t.cast(typ("int32_t")) >> 15 == -2:
        return True

    return False

def intV(o):
    return o['i'].cast(typ("int32_t"))

def noderef(r):
    return mref(r, "Node")

def dump_table(t):
    narr = int(t['asize'])
    nhmask = int(t['hmask'])
    out("table (GCtab*)%#x (narr=%d, nrec=%d):\n" % (ptr2int(t), narr, nhmask))
    arr = tvref(t['array'])
    for i in xrange(narr):
        v = arr[i].address
        if not tvisnil(v):
            out("\t[%d] =\n" % i)
            dump_tvalue(v)

    node = noderef(t['node'])
    for i in xrange(nhmask+1):
        nn = node[i]
        k = nn['key']
        v = nn['val'].address
        if not tvisnil(v):
            out("\tkey:\n")
            dump_tvalue(k)
            out("\tvalue:\n")
            dump_tvalue(v)

def dump_udata(ud, data=False):
    t = ud['udtype']
    out("\t\tudata type: %s\n" % udata_types[int(t)])
    out("\t\t      payload len: %d\n" % int(ud['len']))
    out("\t\t      payload ptr: 0x%x\n" % ptr2int(ud + 1))
    if int(t) == UDTYPE_FFI_CLIB:
        cl = uddata(ud).cast(typ("CLibrary*"))
        out("\t\t      CLibrary handle: (void*)0x%x\n" % \
                ptr2int(cl['handle']))
        out("\t\t      CLibrary cache: (GCtab*)0x%x\n" \
                % ptr2int(cl['cache']))

    if data and int(t) == UDTYPE_USERDATA:
        len = int(ud['len'])
        p = uddata(ud).cast(typ("char *"))
        printlen = min(len, 48)
        out("\t\t      payload header: \"")
        for i in range(printlen):
            #if i in range(32, 126):
            c = p[i]
            if c >= 32 and c <= 126 : #in range(32, 126):
                out("%c" % c)
            else:
                out(".")

        if printlen < len:
            out(" ...")

        out("\"\n")

def dump_tvalue(o, deep=False):
    if tvisudata(o):
        dump_udata(udataV(o))

    elif tvisstr(o):
        gcs = strV(o)
        try:
             out("\t\tstring: \"%s\" (len %d)\n" % (lstr2str(gcs), \
                 int(gcs['len'])))
        except:
               pass

    elif tviscdata(o):
        mL = get_global_L()
        cts = ctype_cts(mL)
        cd = cdataV(o)
        ptr = cdataptr(cd)
        out("\t\ttype cdata\n")
        out("\t\t\tcdata object: (GCcdata*)0x%x\n" % ptr2int(cd))
        out("\t\t\tcdata value pointer: (void*)0x%x\n" % ptr2int(ptr))
        d = ctype_get(cts, cd['ctypeid'])
        out("\t\t\tctype object: (CType*)0x%x\n" % ptr2int(d))
        out("\t\t\tctype size: %d byte(s)\n" % int(d['size']))
        t = int(ctype_type(d['info']))
        #print "ctype type %d\n" % t
        if ctype_names[t]:
            out("\t\t\tctype type: %s\n" % ctype_names[t])
        else:
            err("\t\t\tunknown ctype type: %d\n" % t)
        s = strref(d['name'])
        if s:
            out("\t\t\t\tctype element name: %s\n" % lstr2str(s))

    elif tvislightud(o):
        out("\t\tlight user data: (void*)0x%x\n" % ptr2int(gcrefp(o['gcr'], 'void')))
        return

    elif tvisint(o):
        out("\t\tint %d\n" % int(intV(o)))

    elif tvisnumber(o):
        out("\t\tnumber %.14g\n" % float(o['n']))

    elif tvisnil(o):
        out("\t\tnil\n")

    elif tvistrue(o):
        out("\t\ttrue\n")

    elif tvisfalse(o):
        out("\t\tfalse\n")

    elif tvisfunc(o):
        fn = gcval(o)['fn'].address
        s = fmtfunc(fn)
        out("\t\tfunction %s: (GCfunc*)%#x\n" % (s, ptr2int(fn)))

    elif tvisthread(o):
        th = gcval(o)['th'].address
        out("\t\tthread: (lua_State*)%#x\n" % ptr2int(th))

    elif deep and tvistab(o):
        dump_table(tabV(o))

    else:
        out("\t\t%s: (TValue*)%#x\n" % (ltype(o), ptr2int(o)))

class lval(gdb.Command):
    """This command prints out the content of a TValue* pointer
Usage: lval tv"""

    def __init__ (self):
        super (lval, self).__init__("lval", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) != 1:
            raise gdb.GdbError("Usage: lval tv")

        m = re.match('0x[0-9a-fA-F]+', argv[0])
        if m:
            o = gdb.Value(int(argv[0], 16)).cast(typ("TValue*"))

        else:
            o = gdb.parse_and_eval(argv[0])

        if not o:
            raise gdb.GdbError("table argument empty")
            return

        mL = get_global_L()

        typstr = str(o.type)
        if typstr == "GCstr *":
            out("GCstr: \"%s\" (len %d)\n" % (lstr2str(o), o['len']))
            return

        if typstr == "GCproto *":
            name = proto_chunkname(o)
            if name:
                path = lstr2str(name)
                out("proto definition: %s:%d\n" % (path, int(o['firstline'])))
            begin = proto_bc(o)
            end = begin + o['sizebc']
            out("bytecode range: %#x %#x\n" % (ptr2int(begin), ptr2int(end)))
            return

        if typstr == "GCfunc *":
            out("proto first line: %s\n" % fmtfunc(o))
            if isluafunc(o):
                pt = funcproto(o)
                out("(GCproto*)%#x\n" % ptr2int(pt))
                startpc = (pt.cast(typ("char*")) + typ("GCproto").sizeof).cast(typ("BCIns*"))
                endpc = startpc + pt['sizebc']
                out("proto bc pointer range: %#x %#x\n" % (startpc, endpc))

            return

        if typstr == "GCtab *":
            dump_table(o)
            return

        if typstr == "GCudata *":
            dump_udata(o, True)
            return

        m = re.search(r'TValue', typstr)
        if not m:
            raise gdb.GdbError("TValue * expected, but got %s" % typstr)

        dump_tvalue(o, True)

lval()

class lproto(gdb.Command):
    """This command prints out all the Lua prototypes (the GCproto* pointers) filtered by the file name and file line number where the function is defined.
Usage: lproto file lineno"""

    def __init__ (self):
        super (lproto, self).__init__("lproto", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) != 2:
            raise gdb.GdbError("Usage: lproto file lineno")

        L = get_cur_L()

        fname = str(argv[0])
        lineno = int(argv[1])

        #print "g: ", hex(int(L['glref']['ptr32']))

        g = G(L)

        #print "lineno: %d" % lineno
        #print "file: %s" % fname

        p = g['gc']['root'].address
        while p:
            o = gcref(p)
            if not o:
                break
            if o['gch']['gct'] == ~LJ_TPROTO():
                pt = o['pt'].address
                if pt['firstline'] == lineno:
                    name = proto_chunkname(pt)
                    if name:
                        path = lstr2str(name)
                        if fname in path:
                            out("Found Lua proto (GCproto*)0x%x at %s:%d\n" \
                                    % (ptr2int(pt), path, lineno))
            p = o['gch']['nextgc'].address

lproto()

def uvval(uv_):
    return mref(uv_['v'], 'TValue')

def proto_uvinfo(pt):
    return mref(pt['uvinfo'], 'uint8_t')

def lj_debug_uvname(pt, idx):
    idx = newval("uint32_t", idx)
    p = proto_uvinfo(pt)
    if not p:
        return ""
    if idx:
        while True:
            c = p.dereference()
            p += 1
            if c:
                continue
            idx -= 1
            #print "*p = %d, idx = %d\n" % (int(c), idx)
            if not idx:
                break
    return p.cast(typ("char*")).string('iso-8859-6', 'ignore')

def dump_upvalues(fn, pt):
    uvptr = fn['l']['uvptr']
    sizeuv = int(pt['sizeuv'])
    out("Found %d upvalues.\n" % sizeuv)
    for idx in xrange(0, sizeuv):
        uv = gcref(uvptr[idx])['uv'].address
        tvp = uvval(uv)
        name = lj_debug_uvname(pt, idx)
        out("upvalue \"%s\": value=(TValue*)0x%x value_type=%s closed=%d\n" % \
                (name, ptr2int(tvp), ltype(tvp), int(uv['closed'])))

def find_lfunc_by_src_loc(fname, lineno):
    res = []

    L = get_cur_L()

    #print "g: ", hex(int(L['glref']['ptr32']))

    g = G(L)

    #print "lineno: %d" % lineno
    #print "file: %s" % fname

    p = g['gc']['root'].address
    while p:
        o = gcref(p)
        if not o:
            break
        if o['gch']['gct'] == ~LJ_TFUNC():
            fn = o['fn'].address
            if isluafunc(fn):
                pt = funcproto(fn)
                if pt and pt['firstline'] == lineno:
                    #print "proto: 0x%x\n" % ptr2int(pt)
                    name = proto_chunkname(pt)
                    #print "name: 0x%x\n" % ptr2int(name)
                    #print "len: %d\n" % int(name['len'])
                    if name:
                        path = lstr2str(name)
                        if fname in path:
                            res.append((fn, path))
        p = o['gch']['nextgc'].address
    return res

class lfunc(gdb.Command):
    """This command prints out all the Lua functions (the GCfunc* pointers) filtered by the file name and file line number where the function is defined.
Usage: lfunc file lineno"""

    def __init__ (self):
        super (lfunc, self).__init__("lfunc", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) != 2:
            raise gdb.GdbError("Usage: lfunc file lineno")

        fname = str(argv[0])
        lineno = int(argv[1])

        res = find_lfunc_by_src_loc(fname, lineno)
        for hit in res:
            fn = hit[0]
            path = hit[1]
            out("Found Lua function (GCfunc*)0x%x at %s:%d\n" \
                    % (ptr2int(fn), path, lineno))

lfunc()

class luv(gdb.Command):
    """This command prints out all the upvalues in the GCfunc* pointer specified.
Usage: luv fn"""

    def __init__ (self):
        super (luv, self).__init__("luv", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) != 1:
            raise gdb.GdbError("Usage: luv fn")

        fn = gdbutils.parse_ptr(argv[0], "GCfunc*")
        #print str(fn)
        pt = funcproto(fn)
        dump_upvalues(fn, pt)

luv()

def tvistab(o):
    return itype(o) == LJ_TTAB()

def tvisthread(o):
    return itype(o) == LJ_TTHREAD()

def threadV(o):
    # &gcval(o)->th
    return gcval(o)['th'].address

def tabref(r):
    return gcref(r)['tab'].address

def funcV(o):
    return gcval(o)['fn'].address

class lfenv(gdb.Command):
    """This command prints out the environment table in the input lua object
Usage: lfenv tv"""

    def __init__ (self):
        super (lfenv, self).__init__("lfenv", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) != 1:
            raise gdb.GdbError("Usage: lfenv tv")

        o = gdbutils.parse_ptr(argv[0], "TValue*")

        typstr = str(o.type)
        #print "type: %s\n" % typstr
        if typstr == "lua_State *":
            tab = tabref(o['env'])
            out("environment table: (GCtab*)0x%x\n" % ptr2int(tab))
            return

        if typstr == "GCfunc *":
            t = tabref(o['c']['env'])
            out("(GCtab*)%#x\n" % ptr2int(t))
            return

        if tvisthread(o):
            o = threadV(o)
            tab = tabref(threadV(o['env']))
            out("environment table: (GCtab*)0x%x\n" % ptr2int(tab))

        elif tvisfunc(o):
            t = tabref(funcV(o)['c']['env'])
            out("(GCtab*)%#x\n" % ptr2int(t))

        else:
            out("TODO")

lfenv()

class lg(gdb.Command):
    """This command prints out the global_State * pointer.
Usage: lg [L]"""

    def __init__ (self):
        super (lg, self).__init__("lg", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) == 1:
            L = gdbutils.parse_ptr(argv[0], "lua_State*")
            if not L or str(L) == "void":
                raise gdb.GdbError("L empty")
        else:
            L = get_global_L()

        out("(global_State*)0x%x\n" % ptr2int(G(L)))

lg()

def trace_findfree(J):
    freetrace = 1
    sizetrace = int(J['sizetrace'])
    if sizetrace <= 0:
        return None

    while freetrace < sizetrace:
        if not traceref(J, freetrace):
            return freetrace
        freetrace += 1

    return freetrace

class ltrace(gdb.Command):
    """This command prints out details for the trace specified by the trace number
Usage: ltrace [traceno]"""

    def __init__ (self):
        super (ltrace, self).__init__("ltrace", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 1 and len(argv) != 0:
            raise gdb.GdbError("usage: ltrace [traceno]")

        traceno = None

        if len(argv) >= 1:
            traceno = int(argv[0])

        L = get_global_L()

        g = G(L)
        J = G2J(g)

        freetrace = trace_findfree(J)
        if not freetrace:
            raise gdb.GdbError("No trace found")

        if not traceno:
            ntraces = freetrace - 1
            out("Found %d traces.\n" % ntraces)
            return

        if traceno < 0 or traceno >= freetrace:
            raise gdb.GdbError("trace number out of range: %d" % traceno)

        T = traceref(J, traceno)
        out("(GCtrace*)0x%x\n" % ptr2int(T))
        if not T:
            raise gdb.GdbError("trace %d not valid" % traceno)

        szmcode = int(T['szmcode'])
        out("machine code size: %d\n" % szmcode)
        out("machine code start addr: 0x%x\n" % ptr2int(T['mcode']))
        out("machine code end addr: 0x%x\n" % (ptr2int(T['mcode']) + szmcode))
        pt = gcref(T['startpt'])['pt'].address
        pc = proto_bcpos(pt, mref(T['startpc'], "BCIns"))
        line = lj_debug_line(pt, pc)
        name = proto_chunkname(pt)
        if name:
            path = lstr2str(name)
            out("%s:%d\n" % (path, line))

ltrace()

def bc_op(i):
    return (i & 0xff).cast(typ("BCOp"))

def bc_isret(op):
    op = int(op)
    return (op == BC_RETM or op == BC_RET or op == BC_RET0 or op == BC_RET1)

def locate_pc(pc, verbose):
    """
    L = get_cur_L()
    g = G(L)
    p = g['gc']['root'].address
    while p:
        o = gcref(p)
        if not o:
            break
        if o['gch']['gct'] == ~LJ_TPROTO():
            pt = o['pt'].address
            pos = proto_bcpos(pt, pc) - 1
            if pos <= pt['sizebc'] and pos >= 0:
                out("proto: (GCproto*)0x%x\n" % ptr2int(pt))
                name = proto_chunkname(pt)
                if name:
                    path = lstr2str(name)
                    line = lj_debug_line(pt, pos)
                    out("BC pos: %d\n" % int(pos))
                    out("source line: %s:%d\n" % (path, line))
                    out("proto first line: %d\n" % int(pt['firstline']))
                    return

        p = o['gch']['nextgc'].address

    #print("isret: %d\n" % int(bc_isret(bc_op(pc[-1]))))

    out("no direct match. trying harder...\n")
    """

    pt = pc2proto(pc)
    if not pt:
        out("No matching proto found")
        return

    if verbose:
        out("proto: (GCproto*)0x%x\n" % ptr2int(pt))

    pos = proto_bcpos(pt, pc) - 1
    name = proto_chunkname(pt)
    if name:
        path = lstr2str(name)
        line = lj_debug_line(pt, pos)
        if verbose:
            out("BC pos: %d\n" % int(pos))
        out("source line: %s:%d\n" % (path, line))
        if verbose:
            out("proto first line: %d\n" % int(pt['firstline']))
        return

class lpc(gdb.Command):
    """This command prints out the source line position for the current pc.
Usage: lpc pc"""

    def __init__ (self):
        super (lpc, self).__init__("lpc", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 1:
            raise gdb.GdbError("usage: lpc pc")

        pc = gdbutils.parse_ptr(argv[0], "BCIns*")

        #out("pc type: %s\n" % str(pc.type))

        locate_pc(pc, True)

lpc()

class lringbuf(gdb.Command):
    """This command prints out agentzh's ring buffer in LuaJIT core
Usage: lringbuf"""

    def __init__ (self):
        super (lringbuf, self).__init__("lringbuf", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        rb_var = gdb.lookup_symbol("ringbuffer")[0]
        if rb_var:
            rb = rb_var.value()
            start = gdb.lookup_symbol("rb_start")[0].value()
            end = gdb.lookup_symbol("rb_end")[0].value()
            if start < end:
                i = start
                while i < end:
                    out("%s\n" % rb[i].string('iso-8859-6', 'ignore'))
                    i += 1
            else:
                rblen = gdb.lookup_symbol("rb_full")[0].value()
                if rblen:
                    i = start
                    while i < rblen:
                        out("%s\n" % rb[i].string('iso-8859-6', 'ignore'))
                        i += 1
                    i = 0
                    while i < end:
                        out("%s\n" % rb[i].string('iso-8859-6', 'ignore'))
                        i += 1
                else:
                    if start == 0 and end == 0:
                        out("<empty>\n")
                    else:
                        raise gdb.GdbError("bad thing happened: start=%d, end=%d, full=%d" % (int(start), int(end), int(rblen)))

lringbuf()

class ltracelogs(gdb.Command):
    """This command prints out agentzh's trace logs in LuaJIT core
Usage: ltracelogs"""

    def __init__ (self):
        super (ltracelogs, self).__init__("ltracelogs", gdb.COMMAND_USER)

    def dump_event(self, e):
        event = e["event"]
        if event == 0:
            # trace entry:
            out("->%d L=%#x pc=%#x fn=%#x\n" \
                % (int(e["traceno"]), ptr2int(e["thread"]),
                   ptr2int(e["ins"]), ptr2int(e["fn"])))

        elif event == 1:
            # trace exit
            out("<-%d L=%#x direct_exit=%d exitno=%d pc=%#x fn=%#x\n" \
                % (int(e["traceno"]), ptr2int(e["thread"]),
                   int(e["directexit"]),
                   int(e["exitno"]), ptr2int(e["ins"]), ptr2int(e["fn"])))

        else:
            # trace start
            out("start record %d: L=%#x pc=%#x fn=%#x\n" \
                % (int(e["traceno"]), ptr2int(e["thread"]),
                   ptr2int(e["ins"]), ptr2int(e["fn"])))

    def invoke (self, args, from_tty):
        rb_var = gdb.lookup_symbol("lj_trace_events")[0]
        if not rb_var:
            raise gdb.GdbError("no global variable lj_trace_events found. you lack agentzh's patch for LuaJIT2: http://agentzh.org/misc/luajit/v2.1-trace-logs.patch")

        rb = rb_var.value()
        start = gdb.lookup_symbol("rb_start")[0].value()
        end = gdb.lookup_symbol("rb_end")[0].value()
        if start < end:
            i = start
            while i < end:
                self.dump_event(rb[i])
                i += 1
        else:
            rblen = gdb.lookup_symbol("rb_full")[0].value()
            if rblen:
                i = start
                while i < rblen:
                    self.dump_event(rb[i])
                    i += 1
                i = 0
                while i < end:
                    self.dump_event(rb[i])
                    i += 1
            else:
                if start == 0 and end == 0:
                    out("<empty>\n")
                else:
                    raise gdb.GdbError("bad thing happened: start=%d, end=%d, full=%d" \
                        % (int(start), int(end), int(rblen)))

ltracelogs()

REF_BIAS = 0x8000

irnames = "LT    GE    LE    GT    ULT   UGE   ULE   UGT   EQ    NE    ABC   RETF  NOP   BASE  PVAL  GCSTEPHIOP  LOOP  USE   PHI   RENAMEPROF  KPRI  KINT  KGC   KPTR  KKPTR KNULL KNUM  KINT64KSLOT BNOT  BSWAP BAND  BOR   BXOR  BSHL  BSHR  BSAR  BROL  BROR  ADD   SUB   MUL   DIV   MOD   POW   NEG   ABS   ATAN2 LDEXP MIN   MAX   FPMATHADDOV SUBOV MULOV AREF  HREFK HREF  NEWREFUREFO UREFC FREF  STRREFLREF  ALOAD HLOAD ULOAD FLOAD XLOAD SLOAD VLOAD ASTOREHSTOREUSTOREFSTOREXSTORESNEW  XSNEW TNEW  TDUP  CNEW  CNEWI BUFHDRBUFPUTBUFSTRTBAR  OBAR  XBAR  CONV  TOBIT TOSTR STRTO CALLN CALLA CALLL CALLS CALLXSCARG  "

ircall = [
"lj_str_cmp",
"lj_str_find",
"lj_str_new",
"lj_strscan_num",
"lj_strfmt_int",
"lj_strfmt_num",
"lj_strfmt_char",
"lj_strfmt_putint",
"lj_strfmt_putnum",
"lj_strfmt_putquoted",
"lj_strfmt_putfxint",
"lj_strfmt_putfnum_int",
"lj_strfmt_putfnum_uint",
"lj_strfmt_putfnum",
"lj_strfmt_putfstr",
"lj_strfmt_putfchar",
"lj_buf_putmem",
"lj_buf_putstr",
"lj_buf_putchar",
"lj_buf_putstr_reverse",
"lj_buf_putstr_lower",
"lj_buf_putstr_upper",
"lj_buf_putstr_rep",
"lj_buf_puttab",
"lj_buf_tostr",
"lj_tab_new_ah",
"lj_tab_new1",
"lj_tab_dup",
"lj_tab_clear",
"lj_tab_newkey",
"lj_tab_len",
"lj_gc_step_jit",
"lj_gc_barrieruv",
"lj_mem_newgco",
"lj_math_random_step",
"lj_vm_modi",
"sinh",
"cosh",
"tanh",
"fputc",
"fwrite",
"fflush",
"lj_vm_floor",
"lj_vm_ceil",
"lj_vm_trunc",
"sqrt",
"exp",
"lj_vm_exp2",
"log",
"lj_vm_log2",
"log10",
"sin",
"cos",
"tan",
"lj_vm_powi",
"pow",
"atan2",
"ldexp",
"lj_vm_tobit",
"softfp_add",
"softfp_sub",
"softfp_mul",
"softfp_div",
"softfp_cmp",
"softfp_i2d",
"softfp_d2i",
"softfp_ui2d",
"softfp_f2d",
"softfp_d2ui",
"softfp_d2f",
"softfp_i2f",
"softfp_ui2f",
"softfp_f2i",
"softfp_f2ui",
"fp64_l2d",
"fp64_ul2d",
"fp64_l2f",
"fp64_ul2f",
"fp64_d2l",
"fp64_d2ul",
"fp64_f2l",
"fp64_f2ul",
"lj_carith_divi64",
"lj_carith_divu64",
"lj_carith_modi64",
"lj_carith_modu64",
"lj_carith_powi64",
"lj_carith_powu64",
"lj_cdata_newv",
"lj_cdata_setfin",
"strlen",
"memcpy",
"memset",
"lj_vm_errno",
"lj_carith_mul64",
"lj_carith_shl64",
"lj_carith_shr64",
"lj_carith_sar64",
"lj_carith_rol64",
"lj_carith_ror64",
]

map_regs_Q = [ "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" ]

map_regs_X = [ "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
	"xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15" ]

def regname64(r):
    if r < 16:
        return map_regs_Q[int(r + 1 - 1)]
    return map_regs_X[int(r - 15 - 1)]

irtype = [
  "nil",
  "fal",
  "tru",
  "lud",
  "str",
  "p32",
  "thr",
  "pro",
  "fun",
  "p64",
  "cdt",
  "tab",
  "udt",
  "flt",
  "num",
  "i8 ",
  "u8 ",
  "i16",
  "u16",
  "int",
  "u32",
  "i64",
  "u64",
  "sfp",
]

def ridsp_name(ridsp, ins):
    rid = (ridsp & 0xff)
    slot = (ridsp >> 8)
    if rid == 253 or rid == 254:
        if slot == 0 or slot == 255:
            return " {sink"
        return " {%04d" % (ins - slot)
    if ridsp > 255:
        return "[%x]" % (slot * 4)
    if rid < 128:
        return regname64(rid)
    return ""

def irm_op1(m):
    return (m & 3).cast(typ("IRMode"))

def irm_op2(m):
    return ((m >> 2) & 3).cast(typ("IRMode"))

IRMref = 0

def litname_SLOAD(mode):
    s = ""
    #print("mode=%d\n" % mode)
    if (mode & 1) != 0:
        s += "P"
    if (mode & 2) != 0:
        s += "F"
    if (mode & 4) != 0:
        s += "T"
    if (mode & 8) != 0:
        s += "C"
    if (mode & 16) != 0:
        s += "R"
    if (mode & 32) != 0:
        s += "I"
    return s

irfield = [ "str.len", "func.env", "func.pc", "func.ffid", "thread.env", "tab.meta", "tab.array", "tab.node", "tab.asize", "tab.hmask", "tab.nomm", "udata.meta", "udata.udtype", "udata.file", "cdata.ctypeid", "cdata.ptr", "cdata.int", "cdata.int64", "cdata.int64_4" ]

def litname_irfield(mode):
    return irfield[int(mode)]

def litname_XLOAD(mode):
    a = ["", "R", "V", "RV", "U", "RU", "VU", "RVU"]
    return a[int(mode)]

def litname_CONV(mode):
    s = irtype[int(mode & 31)]
    s = irtype[int((mode >> 5) & 31)] + "." + s
    if (mode & 0x800) != 0:
        s += " sext"
    c = (mode >> 14)
    if c == 2:
        s += " index"
    elif c == 3:
        s += " check"
    return s

irfpm = [ "floor", "ceil", "trunc", "sqrt", "exp", "exp2", "log", "log2", "log10", "sin", "cos", "tan", "other" ]

def litname_FPMATH(mode):
    return irfpm[int(mode)]

def litname_BUFHDR(mode):
    a = ["RESET", "APPEND"]
    return a[int(mode)]

def litname_TOSTR(mode):
    a = ["INT", "NUM", "CHAR"]
    return a[int(mode)]

def litname(op):
    if op == "SLOAD ":
        return litname_SLOAD

    if op == "XLOAD ":
        return litname_XLOAD

    if op == "CONV  ":
        return litname_CONV

    if op == "FLOAD " or op == "FREF  ":
        return litname_irfield

    if op == "FPMATH":
        return litname_FPMATH

    if op == "BUFHDR":
        return litname_BUFHDR

    if op == "TOSTR ":
        return litname_TOSTR

    return None

IR_KSLOT = 30

IR_KPRI = 22
IR_KINT = 23
IR_KGC = 24
IR_KPTR = 25
IR_KKPTR = 26
IR_KNULL = 27
IR_KNUM = 28
IR_KINT64 = 29
IR_KSLOT = 30

def irt_toitype_(t):
    if t > IRT_NUM:
        return "number"

    return ltype(None, ~(t.cast(typ("uint32_t"))))

def irt_type(t):
    return (t['irt'] & IRT_TYPE).cast(typ("IRType"))

def irt_toitype(t):
    return irt_toitype_(irt_type(t))

def ir_kgc(ir):
    return gcref(ir['gcr'])

def ir_knum(ir):
    return mref(ir['ptr'], "TValue")

def ir_kint64(ir):
    return mref(ir['ptr'], 'TValue')

def lj_ir_kvalue(ir):
    t = ir['o']
    if t == IR_KPRI:
        it = irt_toitype(ir['t'])
        return it, it

    if t == IR_KGC:
        it = irt_toitype(ir['t'])
        return ir_kgc(ir), it

    if t == IR_KINT:
        return int(ir['i']), "number"

    if t == IR_KNULL:
        return 0, "userdata"

    if t == IR_KPTR or t == IR_KKPTR:
        return ptr2int(mref(ir['ptr'], "void")), "userdata"

    if t == IR_KNUM:
        return float(ir_knum(ir)['n']), "number"

    if t == IR_KINT64:
        return int(ir_kint64(ir)['u64']), "cdata"

    return "unknown", "unknown"

IRT_TYPE = 0x1f
IRT_NUM = 14

def irt_type(t):
    return (t['irt'] & IRT_TYPE).cast(typ("IRType"))

def tracek(T, idx):
    ref = idx + REF_BIAS
    ir = T['ir'][ref].address
    slot = -1
    if ir['o'] == IR_KSLOT:
        slot = ir['op2']
        ir = T['ir'][ir['op1']].address
    val, it = lj_ir_kvalue(ir)
    t = irt_type(ir['t'])
    if slot == -1:
        return (val, it, t, None)
    return (val, it, t, slot)

ffnames = [
"Lua",
"C",
"assert",
"type",
"next",
"pairs",
"ipairs_aux",
"ipairs",
"getmetatable",
"setmetatable",
"getfenv",
"setfenv",
"rawget",
"rawset",
"rawequal",
"unpack",
"select",
"tonumber",
"tostring",
"error",
"pcall",
"xpcall",
"loadfile",
"load",
"loadstring",
"dofile",
"gcinfo",
"collectgarbage",
"newproxy",
"print",
"coroutine.status",
"coroutine.running",
"coroutine.create",
"coroutine.yield",
"coroutine.resume",
"coroutine.wrap_aux",
"coroutine.wrap",
"math.abs",
"math.floor",
"math.ceil",
"math.sqrt",
"math.log10",
"math.exp",
"math.sin",
"math.cos",
"math.tan",
"math.asin",
"math.acos",
"math.atan",
"math.sinh",
"math.cosh",
"math.tanh",
"math.frexp",
"math.modf",
"math.log",
"math.atan2",
"math.pow",
"math.fmod",
"math.ldexp",
"math.min",
"math.max",
"math.random",
"math.randomseed",
"bit.tobit",
"bit.bnot",
"bit.bswap",
"bit.lshift",
"bit.rshift",
"bit.arshift",
"bit.rol",
"bit.ror",
"bit.band",
"bit.bor",
"bit.bxor",
"bit.tohex",
"string.byte",
"string.char",
"string.sub",
"string.rep",
"string.reverse",
"string.lower",
"string.upper",
"string.dump",
"string.find",
"string.match",
"string.gmatch_aux",
"string.gmatch",
"string.gsub",
"string.format",
"table.maxn",
"table.insert",
"table.concat",
"table.sort",
"table.new",
"table.clear",
"io.method.close",
"io.method.read",
"io.method.write",
"io.method.flush",
"io.method.seek",
"io.method.setvbuf",
"io.method.lines",
"io.method.__gc",
"io.method.__tostring",
"io.open",
"io.popen",
"io.tmpfile",
"io.close",
"io.read",
"io.write",
"io.flush",
"io.input",
"io.output",
"io.lines",
"io.type",
"os.execute",
"os.remove",
"os.rename",
"os.tmpname",
"os.getenv",
"os.exit",
"os.clock",
"os.date",
"os.time",
"os.difftime",
"os.setlocale",
"debug.getregistry",
"debug.getmetatable",
"debug.setmetatable",
"debug.getfenv",
"debug.setfenv",
"debug.getinfo",
"debug.getlocal",
"debug.setlocal",
"debug.getupvalue",
"debug.setupvalue",
"debug.upvalueid",
"debug.upvaluejoin",
"debug.sethook",
"debug.gethook",
"debug.debug",
"debug.traceback",
"jit.on",
"jit.off",
"jit.flush",
"jit.status",
"jit.attach",
"jit.util.funcinfo",
"jit.util.funcbc",
"jit.util.funck",
"jit.util.funcuvname",
"jit.util.traceinfo",
"jit.util.traceir",
"jit.util.tracek",
"jit.util.tracesnap",
"jit.util.tracemc",
"jit.util.traceexitstub",
"jit.util.ircalladdr",
"jit.opt.start",
"jit.profile.start",
"jit.profile.stop",
"jit.profile.dumpstack",
"ffi.meta.__index",
"ffi.meta.__newindex",
"ffi.meta.__eq",
"ffi.meta.__len",
"ffi.meta.__lt",
"ffi.meta.__le",
"ffi.meta.__concat",
"ffi.meta.__call",
"ffi.meta.__add",
"ffi.meta.__sub",
"ffi.meta.__mul",
"ffi.meta.__div",
"ffi.meta.__mod",
"ffi.meta.__pow",
"ffi.meta.__unm",
"ffi.meta.__tostring",
"ffi.meta.__pairs",
"ffi.meta.__ipairs",
"ffi.clib.__index",
"ffi.clib.__newindex",
"ffi.clib.__gc",
"ffi.callback.free",
"ffi.callback.set",
"ffi.cdef",
"ffi.new",
"ffi.cast",
"ffi.typeof",
"ffi.istype",
"ffi.sizeof",
"ffi.alignof",
"ffi.offsetof",
"ffi.errno",
"ffi.string",
"ffi.copy",
"ffi.fill",
"ffi.abi",
"ffi.metatype",
"ffi.gc",
"ffi.load",
]

def fmtfunc(fn):
    if isluafunc(fn):
        pt = funcproto(fn)
        line = int(pt['firstline'])
        name = proto_chunkname(pt)
        if not name:
            return ""
        path = lstr2str(name)
        if path[0] == '@':
            i = len(path) - 1
            while i > 0:
                if path[i] == '/' or path[i] == '\\':
                    path = path[i+1:]
                    break
                i -= 1
        return "%s:%d" % (path, line)

    elif isffunc(fn):
        return ffnames[int(fn['c']['ffid'])]

    else:
        cfunc = fn['c']['f']
        key = str(cfunc)
        if key in cfunc_cache:
            sym = cfunc_cache[key]

        else:
            sym = "C:%s" % cfunc
            m = re.search('<.*?(\w+)*.*?>', cfunc.__str__())
            if m:
                sym = "C:%s" % m.group(1)
            else:
                sym = "C:%s" % key
        return sym

def formatk(tr, idx):
    #return "<k>"
    k, it, t, slot = tracek(tr, idx)
    #print("type: ", it)
    s = None
    if it == "number":
        if k == 2 ** 52 + 2 ** 51:
            s = "bias"
        else:
            #print("BEFORE")
            s = "%+.14g" % k

    elif it == "string":
        k = lstr2str(k.cast(typ("GCstr*")))
        k = re.escape(k).replace("\\_", "_") \
                .replace("\\[", "[") \
                .replace("\\:", ":") \
                .replace("\\ ", " ") \
                .replace("\\]", "]") \
                .replace("\\+", "+") \
                .replace("\\^", "^") \
                .replace("\\*", "*") \
                .replace("\\?", "?") \
                .replace("\\/", "/") \
                .replace("\\\\", "\\")
        if len(k) > 20:
            s = '"%.20s"~' % k
        else:
            s = '"%s"' % k

    elif it == "function":
        s = fmtfunc(k.cast(typ("GCfunc*")))

    elif it == "userdata":
        if t == 12:
            s = "userdata:%#x" % k
        else:
            s = "[%#010x]" % k
            if k == 0:
                s = "[NULL]"
    elif t == 21:  # int64_t
        s = str(k)
        if s[0] != "-":
            s = "+" + s
    else:
        s = str(k)

    s = "%-4s" % s
    if slot:
        s = "%s @%d" % (s, slot)

    return s or "<k>"

def SNAP(slot, flags, ref):
    return (newval("SnapEntry", slot) << 24) + flags + ref

def tracesnap(T, sn):
    if T and sn < T['nsnap']:
        snap = T['snap'][sn].address
        map = T['snapmap'][snap['mapofs']].address
        nent = snap['nent']
        size = nent + 2
        t = []
        int32_t = typ("int32_t")
        t.append(snap['ref'].cast(int32_t) - REF_BIAS)
        t.append(snap['nslots'].cast(int32_t))
        n = 0
        while n < nent:
            t.append(map[n].cast(int32_t))
            n += 1
        t.append(SNAP(255, 0, 0).cast(int32_t))
        return t
    return None

lj_ir_mode = None

def get_ir_mode():
    global lj_ir_mode
    if not lj_ir_mode:
        lj_ir_mode, _ = gdb.lookup_symbol("lj_ir_mode")
        if not lj_ir_mode:
            raise gdb.GdbError("symbol lj_ir_mode not found")
        lj_ir_mode = lj_ir_mode.value()
    return lj_ir_mode

def traceir(T, ins):
    ir_mode = get_ir_mode()

    ref = ins + REF_BIAS
    ir = T['ir'][ref].address
    m = ir_mode[ir['o']]
    ot = ir['ot']
    ofs = 0
    op1 = ir['op1'].cast(typ("int32_t")) - (irm_op1(m) == IRMref and REF_BIAS or 0)
    op2 = ir['op2'].cast(typ("int32_t")) - (irm_op2(m) == IRMref and REF_BIAS or 0)
    ridsp = ir['prev']
    return m, ot, op1, op2, ridsp

def printsnap(T, snap):
    n = 2
    s = 0
    while s <= snap[1] - 1:
        sn = snap[n]
        if (sn >> 24) == s:
            n += 1
            ref = (sn & 0xffff) - REF_BIAS
            if ref < 0:
                out(formatk(T, ref))
            elif (sn & 0x80000) != 0:  # SNAP_SOFTFPNUM
                out("%04d/%04d" % (ref, ref+1))
            else:
                out("%04d" % ref)
            out((sn & 0x10000) == 0 and " " or "|") # SNAP_FRAME
        else:
            out("---- ")
        s += 1
    out("]\n")

def dumpcallargs(T, ins):
    if ins < 0:
        out(formatk(T, ins))
    else:
        m, ot, op1, op2, ridsp = traceir(T, ins)
        oidx = 6 * (ot >> 8)
        op = irnames[int(oidx+1-1):int(oidx+6)]
        if op == "CARG  ":
            dumpcallargs(T, op1)
            if op2 < 0:
                out(" %s" % formatk(T, op2))
            else:
                out(" %04d" % op2)
        else:
            out("%04d" % ins)

def dumpcallfunc(T, ins):
    ctype = None
    if ins > 0:
        m, ot, op1, op2, ridsp = traceir(T, ins)
        if (ot & 31) == 0:
            ins = op1
            ctype = formatk(T, op2)
    if ins < 0:
        k, it, t, slot = tracek(T, ins)
        out("[0x%x](" % k)
    else:
        out("%04d (" % ins)
    return ctype

def pc2loc(pt, pc):
    line = int(lj_debug_line(pt, proto_bcpos(pt, pc) if pc else 0))
    name = proto_chunkname(pt)
    if name:
        path = lstr2str(name)
        if path[0] == '@':
            i = len(path) - 1
            while i > 0:
                if path[i] == '/' or path[i] == '\\':
                    path = path[i+1:]
                    break
                i -= 1
        return "%s:%d" % (path, line)
    else:
        return "?:%d" % line

class lir(gdb.Command):
    """This command prints out all the IR code for the trace specified by its number.
Usage: lir traceno"""

    def __init__ (self):
        super (lir, self).__init__("lir", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 1:
            raise gdb.GdbError("usage: lir traceno")

        traceno = int(argv[0])
        L = get_global_L()

        g = G(L)
        J = G2J(g)

        freetrace = trace_findfree(J)
        if not freetrace:
            raise gdb.GdbError("No trace found")

        if traceno < 0 or traceno >= freetrace:
            raise gdb.GdbError("trace number out of range: %d" % traceno)

        T = traceref(J, traceno)
        if T:
            out("(GCtrace*)0x%x\n" % ptr2int(T))

            instnum = int(T['nins'].cast(typ("int32_t")) - REF_BIAS - 1)
            out("IR count: %d\n\n" % instnum)

            pt = gcref(T['startpt'])['pt'].address
            pc = proto_bcpos(pt, mref(T['startpc'], "BCIns"))
            line = lj_debug_line(pt, pc)
            name = proto_chunkname(pt)
            if name:
                path = lstr2str(name)
                if path[0] == '@':
                    i = len(path) - 1
                    while i > 0:
                        if path[i] == '/' or path[i] == '\\':
                            path = path[i+1:]
                            break
                        i -= 1
                loc = "%s:%d" % (path, line)
            else:
                loc = "unknown"

            root = T['root']

            if root != 0:
                out("---- TRACE %d start %d/? %s\n" % (traceno, root, loc))
            else:
                out("---- TRACE %d start %s\n" % (traceno, loc))

            out("---- TRACE %d IR\n" % traceno)

            snap = tracesnap(T, 0)
            snapref = snap[0]
            snapno = 0

            for ins in range(1, instnum + 1):

                #out("inst ptr: %#x," % ptr2int(ir))

                if ins >= snapref:
                    out("....              SNAP   #%-3d [ " % snapno)
                    printsnap(T, snap)
                    snapno += 1
                    snap = tracesnap(T, snapno)
                    snapref = (snap and snap[0] or 65536)

                m, ot, op1, op2, ridsp = traceir(T, ins)

                oidx = int(6 * (ot >> 8))
                t = int(ot & 31)
                op = irnames[oidx + 1 - 1: oidx + 6]
                #print("op: [%s]\n" % op)

                if op == "LOOP  ":
                    out("%04d ------------ LOOP ------------\n" % ins)
                elif op != "NOP   " and op != "CARG  ":
                    rid = (ridsp & 255)
                    out("%04d %-6s" % (ins, ridsp_name(ridsp, ins)))
                    out("%s%s %s %s " % ((rid == 254 or rid == 253) and "}" or \
                            ((ot & 128) == 0 and " " or ">"),
                            (ot & 64) == 0 and " " or "+",
                            irtype[t], op))
                    m1 = (m & 3)
                    m2 = (m & (3*4))
                    if op[0:4] == "CALL":
                        ctype = None
                        if m2 == 1*4: # op2 == IRMlit
                            out("%-10s  (" % ircall[int(op2)])
                        else:
                            ctype = dumpcallfunc(T, op2)
                        if op1 != -1:
                            dumpcallargs(T, op1)
                        out(")")
                        if ctype:
                            out(" ctype ", ctype)
                    elif op == "CNEW  " and op2 == -1:
                        out(formatk(T, op1))
                    elif m1 != 3:  # op1 != IRMnone
                        if op1 < 0:
                            #print("HERE op1 < 0")
                            out(formatk(T, op1))
                        else:
                            if m1 == 0:
                                out("%04d" % op1)
                            else:
                                out("#%-3d" % op1)
                        if m2 != 3*4:  # op2 != IRMnone
                            if m2 == 1*4:  # op2 == IRMlit
                                litn = litname(op)
                                if litn and litn(op2):
                                    out("  " + litn(op2))
                                elif op == "UREFO " or op == "UREFC ":
                                    out("  #%-3d" % (op2 >> 8))
                                else:
                                    out("  #%-3d" % op2)
                            elif op2 < 0:
                                #print("HERE op2 < 0")
                                out("  %s" % formatk(T, op2))
                            else:
                                out("  %04d" % op2)

                #op1 = int(inst['op1'])
                #op2 = int(inst['op2'])
                #out(" %#x, %#x" % (op1, op2))
                #if name[0:4] == "CALL" :
                    #out(" (%s)" % ircall[op2])
                    #if (op2 & 3) == 4:
                    out("\n")

            if snap:
                out("....              SNAP   #%-3d [ " % snapno)
                printsnap(T, snap)

lir()

class lgc(gdb.Command):
    """This command prints out the current size of memory allocated by the LuaJIT GC.
Usage: lgc [L]"""

    def __init__ (self):
        super (lgc, self).__init__("lgc", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) == 1:
            L = gdbutils.parse_ptr(argv[0], "lua_State*")
            if not L or str(L) == "void":
                raise gdb.GdbError("L empty")
        else:
            L = get_global_L()

        g = G(L)
        out("The current memory size (allocated by GC): %d bytes\n" \
                % int(g['gc']['total']))

lgc()

class lgcstat(gdb.Command):
    """This command prints the statistics of the objects allocated by the LuaJit GC
Usage: lgcstat"""

    def __init__ (self, classname="lgcstat"):
        super (lgcstat, self).__init__(classname, gdb.COMMAND_USER)

    def init_sizeof(self):
        self.TValue_sizeof = typ('TValue').sizeof
        self.GCstr_sizeof = typ("GCstr").sizeof
        self.GCupval_sizeof = typ("GCupval").sizeof
        self.lua_State_sizeof = typ('lua_State').sizeof
        self.GCfuncL_sizeof = typ("GCfuncL").sizeof
        self.GCRef_sizeof = typ("GCRef").sizeof
        self.GCfuncC_sizeof = typ("GCfuncC").sizeof
        self.GCtrace_sizeof = typ("GCtrace").sizeof
        self.Node_sizeof = typ("Node").sizeof
        self.GCtab_sizeof = typ("GCtab").sizeof
        self.GCudata_sizeof = typ("GCudata").sizeof
        self.GCcdataVar_sizeof = typ("GCcdataVar").sizeof
        self.GCcdata_sizeof = typ("GCcdata").sizeof
        self.ptr_sizeof = typ("void*").sizeof

    def invoke (self, args, from_tty):
        begin = time.clock()

        L = get_global_L()
        if not L:
            raise gdb.GdbError("not able to get global_L")

        self.init_sizeof()
        g = G(L)
        ocnt = [ 0 for i in range(int(~LJ_TNUMX()))]
        ototal_sz = [0 for i in range(int(~LJ_TNUMX()))]
        omax = [0 for i in range(int(~LJ_TNUMX()))]
        omin = [0x7fffffff for i in range(int(~LJ_TNUMX()))]

        # step 1: Go through all non-string objects
        o = gcref(g['gc']['root'])
        while o:
            ty = int(o['gch']['gct'])
            ocnt[ty] = ocnt[ty] + 1
            sz = self.get_obj_sz(g, o)
            ototal_sz[ty] += sz;
            omax[ty] = max(omax[ty], sz);
            omin[ty] = min(omin[ty], sz);
            o = gcref(o['gch']['nextgc'])

        # step 2: Go through strings
        for i in range(0, int(1 + g['strmask'])):
            o = gcref(g['strhash'][i])
            ty = int(~LJ_TSTR());
            while o:
                ocnt[ty] = ocnt[ty] + 1
                sz = self.get_obj_sz(g, o)
                ototal_sz[ty] += sz;
                omax[ty] = max(omax[ty], sz);
                omin[ty] = min(omin[ty], sz);
                o = gcref(o['gch']['nextgc'])

        # step 3: Figure out the size of misc data structures
        strhash_size = (g['strmask'] + 1) * typ("GCRef").sizeof
        g_tmpbuf_sz = g['tmpbuf']['e']['ptr32'] - g['tmpbuf']['b']['ptr32']
        jit_state_sz = self.get_jit_state_sz(G2J(g))
        ctype_state_sz = 0
        cts = ctype_ctsG(g)
        if cts:
            ctype_state_sz = typ("CTState").sizeof;
            ctype_state_sz += typ("CType").sizeof * cts['sizetab']

        # step 4: Output the statistics
        ty_name = ["str", "upval", "thread", "proto", "func", "trace", "cdata",
                   "tab", "udata"]
        total_sz = 0
        for i in range(int(~LJ_TNUMX() - ~LJ_TSTR())):
            idx = int(i + ~LJ_TSTR())
            if ocnt[idx] == 0:
               omin[idx] = 0

            total_sz += ototal_sz[idx]

            out ("%4d %-10s objects: max=%d, avg = %d, min=%d, sum=%d\n" %
                 (ocnt[idx], ty_name[i], omax[idx], ototal_sz[idx]/max(1,
                  ocnt[idx]), omin[idx], ototal_sz[idx]))

        out ("\n sizeof strhash %d\n" % strhash_size)
        out (" sizeof g->tmpbuf %d\n" % g_tmpbuf_sz)
        out (" sizeof ctype_state %d\n" % ctype_state_sz)
        out (" sizeof jit_state %d\n" % jit_state_sz)
        total_sz += strhash_size + g_tmpbuf_sz + ctype_state_sz;
        total_sz += typ("GG_State").sizeof - typ("lua_State").sizeof
        total_sz += jit_state_sz

        out ("\ntotal sz %d\n" % total_sz)
        out ("g->strnum %d, g->gc.total %d\n" %
               (int(g['strnum']), int(g['gc']['total'])))

        elapsed = time.clock() - begin
        out("elapsed: %f sec\n" % elapsed)

    def get_jit_state_sz(self, J):
        """
        Return the total size of those non-GC objects that jit_State points
        to.
        """
        sz = 0

        # 64-bit constants:
        #  old revision of luajit: linked list of K64Array
        #  new revision of luajit: array of TValue, a field of jit_State
        try:
            k = mref(J['k64'], "K64Array")
            len = 0;
            while k:
                len += 1
                k = mref(k['next'], "K64Array")
            sz = typ("K64Array").sizeof * len
        except:
            pass

        sz += J['sizesnapmap'] * typ("SnapEntry").sizeof
        sz += J['sizesnap'] * typ("SnapShot").sizeof
        sz += (J['irtoplim'] - J['irbotlim']) * typ("IRIns").sizeof
        sz += J['sizetrace'] * typ("GCRef").sizeof
        return sz

    def get_obj_sz(self, g, o) :
        ty = o['gch']['gct']
        if ty == ~LJ_TSTR():
            return self.GCstr_sizeof + o['str']['len'] + 1

        if ty == ~LJ_TUPVAL():
            return self.GCupval_sizeof

        if ty == ~LJ_TTHREAD():
            th = o['th']
            sz = self.lua_State_sizeof + self.TValue_sizeof * th['stacksize']
            uvref = gcref(th['openupval']);
            while uvref != 0:
                sz += self.get_obj_sz(g, uvref);
                uvref = gcref(uvref['gch']['nextgc'])
            return sz;

        if ty == ~LJ_TPROTO():
            return o['pt']['sizept']

        if ty == ~LJ_TFUNC():
            fn = o['fn']
            if isluafunc(fn):
                sz = self.GCfuncL_sizeof
                sz += self.GCRef_sizeof * (fn['l']['nupvalues'] - 1)
                return sz;
            else:
                sz = self.GCfuncC_sizeof
                sz += self.TValue_sizeof * (fn['c']['nupvalues'] - 1)
                return sz

        if ty == ~LJ_TTRACE():
            T = o.cast(typ("GCtrace*"))
            sz = (self.GCtrace_sizeof + 7) & ~7
            sz += (T['nins'] - T['nk']) * typ("IRIns").sizeof
            sz += T['nsnap'] * typ("SnapShot").sizeof
            sz += T['nsnapmap'] * typ("SnapEntry").sizeof
            return sz;

        if ty == ~LJ_TTAB():
            T = o['tab']
            asize = T['asize']
            hmask = T['hmask']
            colo = T['colo']
            tval_sz = self.TValue_sizeof

            sz = self.GCtab_sizeof
            if hmask > 0:
                sz += self.Node_sizeof * (hmask + 1)

            if asize > 0 and colo <= 0:
                sz += tval_sz * asize

            if colo != 0:
                sz += (colo & 0x7f) * tval_sz

            return sz

        if ty == ~LJ_TUDATA():
            return self.GCudata_sizeof + o['ud']['len']

        if ty == ~LJ_TCDATA():
            cd = o['cd']
            if cd['marked'] & 0x80:
               # is vector
               addr = o.cast(typ("char*")) - self.GCcdataVar_sizeof
               cdv = addr.cast(typ("GCcdataVar*"))
               return cdv['len'] + cdv['extra']

            sz = self.GCcdata_sizeof
            cts = ctype_ctsG(g)
            cts_tab = cts['tab']
            cty = cts_tab[cd['ctypeid']]
            while ctype_type(cty['info']) == CT_ATTRIB:
                cty = cts_tab[cty['info'] & CTMASK_CID]

            if ctype_type(cty['info']) <= CT_HASSIZE:
                sz += cty['size']
            else:
                sz += self.ptr_sizeof
            return sz

        return 0

lgcstat()

class lgcpath(lgcstat):
    """Given the size and optionally the type, this command print a path of GC
       reference graph from root to an object of same type (if type is specified)
       and whose size is no less than the specified size
       Usage: lgcpath size [type]"""

    def __init__ (self):
        super (lgcpath, self).__init__("lgcpath")
        self.baseclass = super(lgcpath, self)
        self.init_datamembers()
        self.obj_ty = ""

    def init_datamembers(self):
        self.gc_path = []
        self.visited = {}
        self.path_idx = 0
        self.obj_size = 0
        self.obj_annot = {}
        self.path_root = 0

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) == 1:
            self.objsize = gdb.parse_and_eval(argv[0])
        elif len(argv) == 2:
            self.objsize = gdb.parse_and_eval(argv[0])
            self.obj_ty = argv[1]
        else:
            raise gdb.GdbError("Usage: lgcpath objsize [udata|str|tab|thr|upval|func|tr]")

        if not self.objsize:
            raise gdb.GdbError("object size is not specified")

        L = get_global_L()
        if not L:
            raise gdb.GdbError("not able to get global_L")

        # step 0: Init
        self.init_datamembers()
        # Otherwise, get_obj_sz() doesn't work as expected
        self.baseclass.init_sizeof()
        self.visited.clear()

        # step 1: DFS registry 
        g = G(L)
        self.path_root = 1
        self.visit_tval(g['registrytv'], g)

        # step 2: DFS main thread
        self.path_root = 2
        thr = gcref(g['mainthref'])['th'].address
        self.dfs(thr, g)

        # step 3: DFS env
        self.path_root = 3
        self.dfs(gcref(thr['env']), g)

        # step 4: dfs GCROOTs
        self.path_root = 4
        gcroot = g['gcroot']
        for idx in range(GCROOT_MAX):
            ref = gcroot[idx]
            if newval("int", ref) != 0:
                self.dfs(gcref(ref), g)

        if self.path_idx == 0:
            out("No GC object of size %d\n" % self.objsize)

    def is_visited(self, n):
        try:
            dummy = self.visited[ptr2int(n)]
            return 1
        except:
            return 0

    def set_visited(self, n):
        self.visited[ptr2int(n)] = 1

    def print_str(self, str, g):
        len = int(str['len'])
        out("->str \"")

        # print the content
        p = str.cast(typ("char*"))
        p += typ("GCstr").sizeof
        printlen = min(len, 48)
        for i in range(printlen):
            #if i in range(32, 126):
            c = p[i]
            if c >= 32 and c <= 126 : #in range(32, 126):
                out("%c" % c)
            else:
                out(".")

        if printlen < len:
            out(" ...")

        out("\") ")

    def print_func(self, fn, g):
        if isluafunc(fn):
            out("->lfunc")
            proto = funcproto(fn)
            name = proto_chunkname(proto)
            if name:
                path = lstr2str(name)
                out("(%s:%d)" % (path, int(proto['firstline'])))
        else:
            out("->cfunc")

        fnaddr = ptr2int(fn)
        try:
            annot = self.obj_annot[fnaddr]
        except:
            annot = 0
        component = annot >> 30
        idx = annot & ((1<<30) - 1)
        if component == 1:
            out (" ->env")
        elif component == 2:
            uvname = lj_debug_uvname(proto, idx)
            out (" ->upval[%d](%s)" % (idx, uvname))

        out(" ")

    def print_thread(self, thr, g):
        thraddr = ptr2int(thr)
        out("->thr(ptr:%#x)" % thraddr)

        try:
            annot = self.obj_annot[thraddr]
        except:
            annot = 0

        component = annot >> 30
        idx = annot & ((1<<30) - 1)

        if component == 1:
            out(" ->env")
        elif component == 2:
            out(" ->stack[%d]" % idx)
        elif component == 3:
            out(" ->frame[%d]" % idx)
        out(" ")

    def tv2str(self, tv):
        if tvisstr(tv):
            gcs = strV(tv)
            return '"' + lstr2str(gcs) + '"'
        elif tvisint(tv):
            return "%d" % int(intV(tv))
        elif tvisnumber(tv):
            return "%.14g" % float(tv['n'])
        elif tvisnil(tv):
            return "nil"
        elif tvistrue(tv):
            return "true"
        elif tvisfalse(tv):
            return "false"
        else:
            return "tv=%#x" % ptr2int(tv)

    def print_tab(self, tab, g):
        tabaddr = ptr2int(tab)
        out("->Tab")

        try:
            annot = self.obj_annot[tabaddr]
        except:
            annot = 0

        component = annot >> 30
        idx = annot & ((1<<30) - 1)
        if component >= 1 and component <= 4:
            if component == 1:
                out(":metatab:")
            elif component == 2:
                out("[%d]" % idx)
            elif component == 3:
                out("-key#%d" % idx)
            elif component == 4:
                node_ptr = noderef(tab['node'])
                n = node_ptr[idx].address
                s = self.tv2str(n['key'].address)
                out("[%s]" % s)

        out(" ")

    def print_proto(self, proto, g):
        name = proto_chunkname(proto)
        if name:
            path = lstr2str(name) 
            out("proto(%s:%d)" % (path, int(proto['firstline'])))
        else:
            out("proto ")

    def print_obj_path(self, g):
        # print 16 paths at most
        if self.path_idx == 16:
            return

        if self.path_idx == 15:
            self.path_idx = 16
            out("... more paths ...\n")
            return

        out ("path %03d:" % self.path_idx)
        if self.path_root == 1:
            out("[registry] ")
        elif self.path_root == 2:
            out("[main-thr] ")
        elif self.path_root == 3:
            out("[env] ")
        elif self.path_root == 4:
            out("[gcroots] ")

        self.path_idx = self.path_idx  + 1
        for o in self.gc_path:
            obj = o.cast(typ("GCobj*"))
            ty = obj['gch']['gct']
            if ty == ~LJ_TTAB() :
                self.print_tab(obj.cast(typ("GCtab*")), g)
            elif ty == ~LJ_TFUNC() :
                self.print_func(obj.cast(typ("GCfunc*")), g)
            elif ty == ~LJ_TPROTO() :
                self.print_proto(obj.cast(typ("GCproto*")), g)
            elif ty == ~LJ_TTHREAD() :
                self.print_thread(obj.cast(typ("lua_State*")), g)
            elif ty == ~LJ_TTRACE() :
                out("-> trace(id:%d) " % obj.cast(typ("GCtrace*"))['traceno'])
            elif ty == ~LJ_TUDATA() :
                out("-> user-data ")
            elif ty == ~LJ_TUPVAL():
                out("-> uv ")
            elif ty == ~LJ_TCDATA():
                out("-> cdata ")
            elif ty == ~LJ_TSTR():
                self.print_str(obj.cast(typ("GCstr*")), g)
            else:
                out(" unknown ty obj")

        # print the size of last GC object in the path
        gco = self.gc_path[-1].cast(typ("GCobj*"))
        sz = self.get_obj_sz(g, gco)
        out("sz:%d (GCobj*)%#x ->END\n" % (sz, ptr2int(gco)))

    def is_intersted_ty(self, ty):
        if not self.obj_ty:
            return True

        if ((ty == ~LJ_TSTR() and self.obj_ty == "str") or \
            (ty == ~LJ_TTAB() and self.obj_ty == "tab") or
            (ty == ~LJ_TTHREAD() and self.obj_ty == "thr") or
            (ty == ~LJ_TUPVAL() and self.obj_ty == "upval") or
            (ty == ~LJ_TFUNC() and self.obj_ty == "func") or
            (ty == ~LJ_TUDATA() and self.obj_ty == "udata") or
            (ty == ~LJ_TTRACE() and self.obj_ty == "tr")):
             return True

        return False

    def dfs(self, o, g):
        if self.path_idx == 16:
            return

        if self.is_visited(o) != 0:
            return
        self.set_visited(o)

        # Step 1: Keep track of object-path
        self.gc_path.append(o)

        # Step 2: In case this object is what we are looking for, print
        #  the path from GC-ROOT to this object
        obj = o.cast(typ("GCobj*"))
        ty = obj['gch']['gct']
        sz = self.baseclass.get_obj_sz(g, obj)
        if sz >= self.objsize and self.is_intersted_ty(ty):
          self.print_obj_path(g)

        # Step 3: Visit the GC object
        if ty == ~LJ_TSTR():
            pass
        elif ty == ~LJ_TTAB() :
            self.visit_tab(obj['tab'].address, g)
        elif ty == ~LJ_TFUNC() :
            self.visit_func(obj['fn'].address, g)
        elif ty == ~LJ_TPROTO() :
            self.visit_proto(obj['pt'].address, g)
        elif ty == ~LJ_TTHREAD() :
            self.visit_thread(obj['th'].address, g)
        elif ty == ~LJ_TTRACE():
            self.visit_trace(o.cast(typ('GCtrace*')) ,g)
        elif ty == ~LJ_TUDATA() or ty == ~LJ_TUPVAL() or ty == ~LJ_TCDATA():
            pass
        else:
            raise gdb.GdbError("unknown ty %d" % ty)

        # step 4: Keep track of object-path
        self.gc_path.pop()

    def visit_tval(self, tv, g):
        if (tvisgcv(tv)):
           self.dfs(gcval(tv), g)

    def visit_thread(self, thr, g) :
        thraddr = ptr2int(thr)

        # Step 1: Visit the env table
        self.obj_annot[thraddr] = 1<<30
        self.dfs(tabref(thr['env']), g)

        # Step 2: Iterate all TValues in the stack; if the TValue being visited
        # holds a reference to a GC object, DFS forward from the object.
        #
        iter = tvref(thr['stack']) + 1
        top = thr['top']
        idx = 1
        while iter < top:
            self.obj_annot[thraddr] = ((2<<30) | idx)
            self.visit_tval(iter, g)
            idx = idx + 1
            iter = iter + 1

        # Step 3: Go through all functions in the call-chain.
        #
        # Question: How to visit those function which were created before,
        #  but are not showing up on the call-chain?
        #
        frame = thr['base'] - 1 # starting from current function
        bottom = tvref(thr['stack'])
        idx = 0;
        while frame > bottom:
            fn = frame_func(frame)
            self.obj_annot[thraddr] = ((3<<30) | idx)
            self.dfs(fn, g)
            frame = frame_prev(frame)
            idx = idx + 1

        del self.obj_annot[thraddr]

    def visit_tab(self, tab, g) :
        tabaddr = ptr2int(tab)

        mt = tabref(tab['metatable'])
        if mt != 0:
            self.obj_annot[tabaddr] = 1<<30
            self.dfs(mt, g)

        # TODO: check if key and/or value is weak

        # Loop over elements of array part
        for i in xrange(int(tab['asize'])):
            tv = tvref(tab['array'])[i].address
            if tvisgcv(tv):
                self.obj_annot[tabaddr] = ((2<<30)|i)
                self.dfs(gcval(tv), g)

        # Loop over elements of hash part
        hmask = tab['hmask']
        if hmask > 1:
            node_ptr = noderef(tab['node'])
            for i in range(int(hmask + 1)):
                n = node_ptr[i].address
                if not tvisnil(n['val'].address):
                    tv = n['key']
                    if tvisgcv(tv):
                        self.obj_annot[tabaddr] = ((3<<30)|i)
                        self.dfs(gcval(tv), g)

                    tv = n['val']
                    if tvisgcv(tv):
                        self.obj_annot[tabaddr] = ((4<<30)|i)
                        self.dfs(gcval(tv), g)

        # Remove the annotation
        try:
            del self.obj_annot[tabaddr]
        except:
            pass

    def visit_func(self, fn, g):
        fnaddr = ptr2int(fn)
        self.obj_annot[fnaddr] = 1<<30
        if isluafunc(fn):
            self.dfs(funcproto(fn), g)
            uvptr = fn['l']['uvptr']
            for i in range(int(fn['l']['nupvalues'])):
                self.obj_annot[fnaddr] = (2<<30) | i
                self.dfs(gcref(uvptr[i])['uv'].address, g)
        else:
            uvptr = fn['c']['upvalue'][0].address
            for i in range(int(fn['c']['nupvalues'])):
                self.obj_annot[fnaddr] = (1<<30) | i
                self.visit_tval(uvptr[i], g)

        self.dfs(tabref(fn['c']['env']), g)
        del self.obj_annot[fnaddr]

    def visit_trace(self, tr, g):
        pass
#        ref = tr['nk']
#        while ref < REF_BIAS - 3:
#            ir = tr['ir'][ref].address
#            if ir['o'] == IR_KGC:
#                self.dfs(obj2gco(ir_kgc(ir)), g)
#            ref = ref + 1
#
#        t = tr['link']
#        if t != 0:
#            self.dfs(obj2gco(traceref(G2J(g), t)), g)
#
#        t = tr['nextroot']
#        if t != 0:
#            self.dfs(obj2gco(traceref(G2J(g), t)), g)
#
#        t = tr['nextside']
#        if t != 0:
#            self.dfs(obj2gco(traceref(G2J(g), t)), g)

    def visit_proto(self, pt, g):
        # Step 1: visit chunk name
        self.dfs(proto_chunkname(pt), g)

        # Step 2: (TODO) viist proto_kgc()s'

        # Step 3: visit traces
        trno = pt['trace']
        if trno != 0:
            tr = obj2gco(traceref(G2J(g), trno))
            self.dfs(tr, g)

lgcpath()

lj_bc_mode = None

bcnames = "ISLT  ISGE  ISLE  ISGT  ISEQV ISNEV ISEQS ISNES ISEQN ISNEN ISEQP ISNEP ISTC  ISFC  IST   ISF   ISTYPEISNUM MOV   NOT   UNM   LEN   ADDVN SUBVN MULVN DIVVN MODVN ADDNV SUBNV MULNV DIVNV MODNV ADDVV SUBVV MULVV DIVVV MODVV POW   CAT   KSTR  KCDATAKSHORTKNUM  KPRI  KNIL  UGET  USETV USETS USETN USETP UCLO  FNEW  TNEW  TDUP  GGET  GSET  TGETV TGETS TGETB TGETR TSETV TSETS TSETB TSETM TSETR CALLM CALL  CALLMTCALLT ITERC ITERN VARG  ISNEXTRETM  RET   RET0  RET1  FORI  JFORI FORL  IFORL JFORL ITERL IITERLJITERLLOOP  ILOOP JLOOP JMP   FUNCF IFUNCFJFUNCFFUNCV IFUNCVJFUNCVFUNCC FUNCCW"

def funcbc(pc):
    ins = pc[0]
    op = bc_op(ins)
    global lj_bc_mode
    if not lj_bc_mode:
        sym = gdb.lookup_symbol("lj_bc_mode")[0]
        if not sym:
            raise gdb.GdbError("global symbol lj_bc_mode not found")
        lj_bc_mode = sym.value()

    return ins, lj_bc_mode[op]

def ctlsub(s):
    return s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")

def pc2proto(pc):
    i = 0
    while pc and i < 1000000:
        ins = pc[-i]
        #print("ins: %d" % int(ins))
        oidx = int(6 * (ins & 0xff))
        op = bcnames[oidx:oidx+6]
        #print("op: %s" % op)
        if op == "FUNCF " or op == "FUNCV " or op == "JFUNCF" \
           or op == "JFUNCV" or op == "IFUNCF" or op == "IFUNCV":
            return ((pc - i).cast(typ("char*")) - typ("GCproto").sizeof).cast(typ("GCproto*"))
        i += 1
    return None

def proto_kgc(pt, idx):
    return gcref(mref(pt['k'], "GCRef")[idx])

def proto_knumtv(pt, idx):
    return gcval(mref(pt['k'], "TValue") + idx)

def funck(pt, idx):
    #print "idx = %d, sizekn=%d, sizekgc=%d" % (idx, pt['sizekn'], \
            #pt['sizekgc'])
    if idx >= 0:
        if idx < pt['sizekn']:
            return proto_knumtv(pt, idx)
    else:
        if ~idx < pt['sizekgc']:
            return proto_kgc(pt, idx)
    return None

def funcuvname(pt, idx):
    if idx < pt['sizeuv']:
        return lj_debug_uvname(pt, idx)
    return None

def bcline(func, pc, prefix):
    ins, m = funcbc(pc)
    if not ins:
        #print "no ins!"
        return None

    ma, mb, mc = m & 7, m & (15*8), m & (15*128)
    a = (ins >> 8) & 0xff
    oidx = int(6 * (ins & 0xff))
    op = bcnames[oidx:oidx+6]

    s = "%04d %s %-6s %3s " % (proto_bcpos(func, pc), prefix or "  ", \
            op, "" if ma == 0 else a)
    d = ins >> 16
    #print "1: d = %d" % d
    if mc == 13*128:  # BCMjump
        return "%s=> %04d\n" % (s, int(proto_bcpos(func, pc)+d-0x7fff))
    if mb != 0:
        d = d & 0xff
    elif mc == 0:
        return s + "\n"

    #print "2: d = %d" % d

    kc = None
    if mc == 10*128:  # BCMstr
        k = funck(func, -int(d)-1)
        #print(type(k))
        kc = lstr2str(k.cast(typ("GCstr*")))
        kc = ctlsub(kc)
        if len(kc) > 40:
            kc = '"%.40s"~' % kc
        else:
            kc = '"%s"' % kc
        #print("%s" % kc)
    elif mc == 9*128:  # BCMnum
        kc = funck(func, d)
        if op == "TSETM ":
            kc = kc - 2**52
    elif mc == 12*128:  # BCMfunc
        pt = funck(func, -int(d)-1).cast(typ("GCproto*"))
        kc = pc2loc(pt, None)
    elif mc == 5*128:  # BCMuv
        kc = funcuvname(func, d)
    if ma == 5:   # BCMuv
        ka = funcuvname(func, a)
        if kc:
            kc = ka + " ; " + kc
        else:
            kc = ka
    if mb != 0:
        b = ins >> 24
        if kc:
            return "%s%3d %3d  ; %s\n" % (s, b, d, kc)
        return "%s%3d %3d\n" % (s, b, d)
    if kc:
        return "%s%3d      ; %s\n" % (s, d, kc)
    if mc == 7*128 and d > 32767:  # BCMlits
        d = d - 65536
    return "%s%3d\n" % (s, d)

class lbc(gdb.Command):
    """This command prints out the LuaJIT bytecode in the PC range specified by the user.
Usage: lbc <from> <to>"""

    def __init__ (self):
        super (lbc, self).__init__("lbc", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 2:
            raise gdb.GdbError("usage: lbc <from> <to>")

        fr = gdb.parse_and_eval(argv[0]).cast(typ("BCIns*"))
        to = gdb.parse_and_eval(argv[1]).cast(typ("BCIns*"))

        pt = pc2proto(fr)
        if not pt:
            raise gdb.GdbError("failed to find the GCproto context")
        end = fr + pt['sizebc']

        out("(GCproto*)%#x\n" % ptr2int(pt))
        out("-- BEGIN BYTECODE -- %s\n" % pc2loc(pt, fr))

        if fr > to:
            raise gdb.GdbError("error: <from> is greater than <to>")

        pc = fr
        while pc < to:
            #print "pc=%#x, to=%#x" % (ptr2int(pc), ptr2int(to))
            if pc == end:
                out("-------- END PROTO ---------\n")

            line = bcline(pt, pc, None)
            if not line:
                #print("not line")
                break
            out("%s" % line)
            pc += 1

        if pc == to:
            out("-- END BYTECODE -- %s\n" % pc2loc(pt, to))
        else:
            out("-- ABROT BYTECODE -- %s\n" % pc2loc(pt, pc - 1))

lbc()


class lcq(gdb.Command):
    """This command checks the expiration times in the "cache_queue" queue with the current time (in seconds) specified
Usage: lcq <from> <to>"""

    def __init__ (self):
        super (lcq, self).__init__("lcq", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 2:
            raise gdb.GdbError("usage: lcq <cache_queue_ptr> <time>")

        head = gdb.parse_and_eval(argv[0]).cast(typ("lrucache_pureffi_queue_t*"))
        time = int(argv[1])

        node = head['next']
        while node != head:
            diff = node['expire'] - time
            out("ttl: %f\n" % diff)
            node = node['next']

lcq()

LUA_YIELD = 1

class lthreadpc(gdb.Command):
    """This command prints out the next PC to be executed for a yielded Lua thread.
Usage: lthreadpc <L>"""

    def __init__ (self):
        super (lthreadpc, self).__init__("lthreadpc", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 1:
            raise gdb.GdbError("usage: lthreadpc <L>")

        L = gdb.parse_and_eval(argv[0]).cast(typ("lua_State*"))

        if L['cframe'] == null() and L['status'] <= LUA_YIELD:
            pc = (L['base'].cast(typ("char*")) - 4).cast(typ("uint32_t*")).dereference()
            out("next PC: (BCIns*)%#x\n" % pc)
            locate_pc(pc.cast(typ("BCIns*")), False)
        else:
            raise gdb.GdbError("Lua thread in bad state")

lthreadpc()

class rawheader(gdb.Command):
    def __init__ (self):
        super (rawheader, self).__init__("rawheader", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 1:
            raise gdb.GdbError("usage: lthreadpc <r>")

        r = gdb.parse_and_eval(argv[0]).cast(typ("ngx_http_request_t*"))

        mr = r['main']
        hc = mr['http_connection']
        c = mr['connection']

        size = 0
        b = c['buffer']

        if mr['request_line']['data'][mr['request_line']['len']] == newval("unsigned char", 13):
            line_break_len = 2
        else:
            line_break_len = 1

        first = None

        if mr['request_line']['data'] >= b['start'] \
                and mr['request_line']['data'] + mr['request_line']['len'] + line_break_len <= b['pos']:
            first = b

            if mr['header_in'] == b:
                size += mr['header_in']['pos'] - mr['request_line']['data']
            else:
                p = b['pos']
                size += p - mr['request_line']['data']

                while b['pos'] > b['start'] and b['pos'][-1] != newval("unsigned char", 10):
                    size -= 1

        if hc['nbusy']:
            b = null()

        for i in xrange(0, int(hc['nbusy'])):
            b = hc['busy'][i]

            if not first:
                if mr['request_line']['data'] >= b['pos'] \
                        or mr['request_line']['data'] + mr['request_line']['len'] + line_break_len <= b['start']:
                    continue

                first = b

            if b == mr['header_in']:
                size += mr['header_in']['pos'] - b['start']
                break

            size += b['pos'] - b['start']

        size += 1
        last = 0

        b = c['buffer']
        if first == b:
            raise gdb.GdbError("not implemented")

        if hc['nbusy']:
            found = (b == c['buffer'])
            for i in xrange(0, int(hc['nbusy'])):
                b = hc['busy'][i]

                if not found:
                    if b != first:
                        continue
                    found = 1

                p = last

                if b == mr['header_in']:
                    pos = mr['header_in']['pos']
                else:
                    pos = b['pos']

                if b == first:
                    last += pos - mr['request_line']['data']
                else:
                    last += pos - b['start']

                # skip truncated header entries (if any)

                if b == mr['header_in']:
                    break

        last += 0
        if last > size:
            raise gdb.GdbError("buffer error: " + (last - size))

rawheader()

class ltracebymcode(gdb.Command):
    """This command prints out the trace by an included machine code address.
Usage: ltracebymcode [addr]"""

    def __init__ (self):
        super (ltracebymcode, self).__init__("ltracebymcode", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 1:
            raise gdb.GdbError("usage: ltracebymcode addr")

        addr = None

        addr = gdbutils.parse_ptr(argv[0], "void*")

        L = get_global_L()

        g = G(L)
        J = G2J(g)

        freetrace = trace_findfree(J)
        if not freetrace:
            raise gdb.GdbError("No trace found")

        for traceno in xrange(1, freetrace):

            T = traceref(J, traceno)
            start = T['mcode']
            szmcode = int(T['szmcode'])

            if addr >= start and addr <= start + szmcode:
                if not T:
                    raise gdb.GdbError("trace %d not valid" % traceno)

                out("(GCtrace*)0x%x (trace #%d)\n" % (ptr2int(T), traceno))
                out("machine code start addr: 0x%x\n" % ptr2int(start))
                out("machine code end addr: 0x%x\n" % (ptr2int(start) + szmcode))
                pt = gcref(T['startpt'])['pt'].address
                pc = proto_bcpos(pt, mref(T['startpc'], "BCIns"))
                line = lj_debug_line(pt, pc)
                name = proto_chunkname(pt)
                if name:
                    path = lstr2str(name)
                    out("%s:%d\n" % (path, line))

ltracebymcode()

FuncEntryTargets = {}
FuncEntryMatchAll = False

FuncEntryBPs = []

class BCCallMBP (gdb.Breakpoint):
    def __init__ (self):
        super (BCCallMBP, self).__init__("lj_BC_CALLM")

    def stop (self):
        RA = gdb.parse_and_eval("$ecx")
        BASE = gdb.parse_and_eval("$edx").cast(typ("TValue*"))
        fntv = BASE[RA]

        hit = False
        global FuncEntryMatchAll
        if FuncEntryMatchAll:
            hit = True

        else:
            global FuncEntryTargets
            fn = gcval(fntv)['fn'].address
            if ptr2int(fn) in FuncEntryTargets:
                hit = True

        if not hit:
            return False

        MULTRES = int(gdb.parse_and_eval("$rsp").cast(typ("uint32_t*"))[1])
        #out("multres: %d" % MULTRES)
        out("Entry breakpoint hit at\n")
        dump_tvalue(fntv)
        pc = gdb.parse_and_eval("$ebx").cast(typ("BCIns*")) - 1
        locate_pc(pc, False)
        RC = gdb.parse_and_eval("$al") + MULTRES
        RC -= 1

        if RC == 0:
            out("Taking no arguments.\n")

        else:
            out("Taking %d arguments:\n" % RC)
            for i in xrange(0, RC):
                dump_tvalue(BASE[RA + 1 + i])

        return True

class BCCallBP (gdb.Breakpoint):
    def __init__ (self):
        super (BCCallBP, self).__init__("lj_BC_CALL")

    def stop (self):
        RA = gdb.parse_and_eval("$ecx")
        BASE = gdb.parse_and_eval("$edx").cast(typ("TValue*"))
        fntv = BASE[RA]

        hit = False
        global FuncEntryMatchAll
        if FuncEntryMatchAll:
            hit = True

        else:
            global FuncEntryTargets
            fn = gcval(fntv)['fn'].address
            if ptr2int(fn) in FuncEntryTargets:
                hit = True

        if not hit:
            return False

        out("Entry breakpoint hit at\n")
        dump_tvalue(fntv)
        pc = gdb.parse_and_eval("$ebx").cast(typ("BCIns*")) - 1
        locate_pc(pc, False)
        RC = gdb.parse_and_eval("$al")
        RC -= 1

        if RC == 0:
            out("Taking no arguments.\n")

        else:
            out("Taking %d arguments:\n" % RC)
            for i in xrange(0, RC):
                dump_tvalue(BASE[RA + 1 + i])

        return True

class BCCallTBP (gdb.Breakpoint):
    def __init__ (self):
        super (BCCallTBP, self).__init__("lj_BC_CALLT")

    def stop (self):
        RA = gdb.parse_and_eval("$ecx")
        BASE = gdb.parse_and_eval("$edx").cast(typ("TValue*"))
        fntv = BASE[RA]

        hit = False
        global FuncEntryMatchAll
        if FuncEntryMatchAll:
            hit = True

        else:
            global FuncEntryTargets
            fn = gcval(fntv)['fn'].address
            if ptr2int(fn) in FuncEntryTargets:
                hit = True

        if not hit:
            return False

        out("Entry breakpoint hit at\n")
        dump_tvalue(fntv)
        pc = gdb.parse_and_eval("$ebx").cast(typ("BCIns*")) - 1
        #out("pc = %#x" % ptr2int(pc))
        locate_pc(pc, False)
        RD = gdb.parse_and_eval("$eax")
        RD -= 1
        out("Taking %d arguments:\n" % RD)
        for i in xrange(0, RD):
            dump_tvalue(BASE[RA + 1 + i])
        return True

def matchAny(fn):
    return True

class lb(gdb.Command):
    """This command sets a breakpoint on (interpreted) Lua function call entries
Usage: lb <spec>"""

    def __init__ (self):
        super (lb, self).__init__("lb", gdb.COMMAND_USER)

    src_line_pat = re.compile("(\S+):(\d+)")

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 1:
            raise gdb.GdbError("usage: lb <spec>")

        global FuncEntryMatchAll, FuncEntryBPs, FuncEntryTargets

        spec = argv[0]
        #out("spec = %s\n" % spec)
        if spec == "*":
            FuncEntryMatchAll = True

        else:
            m = re.match(lb.src_line_pat, spec)
            if m is not None:
                fname = m.group(1)
                lineno = int(m.group(2))

                #if FuncEntryMatchAll:
                    #raise gdb.GdbError("Breakpoint already set on all Lua function entries")

                out("Searching Lua function at %s:%d...\n" % (fname, lineno))
                res = find_lfunc_by_src_loc(fname, lineno)
                found = False
                for hit in res:
                    fn = hit[0]
                    path = hit[1]
                    out("Set break point on (GCfunc*)%#x at %s:%d\n" \
                        % (ptr2int(fn), path, lineno))
                    FuncEntryTargets[ptr2int(fn)] = spec
                    found = True

                if not found:
                    raise gdb.GdbError("failed to find Lua function matching %s" \
                            % spec)
            else:
                raise gdb.GdbError("Bad spec: %s" % spec)

        if not FuncEntryBPs:
            FuncEntryBPs.append(BCCallBP())
            FuncEntryBPs.append(BCCallTBP())
            FuncEntryBPs.append(BCCallMBP())
            # lj_BC_CALLMT is already covered by lj_BC_CALLT

        else:
            # validate the break points to protect against user
            # removal
            for bp in FuncEntryBPs:
                if not bp.is_valid():
                    bp.__init__()

lb()

def removeAllEntryBPs():
    FuncEntryTargets.clear()

    for bp in FuncEntryBPs:
        if not bp.is_valid():
            bp.delete()

    try:
        gdb.execute("clear lj_BC_CALL")
        gdb.execute("clear lj_BC_CALLM")
        gdb.execute("clear lj_BC_CALLT")

    except:
        pass

def removeAllReturnBPs():
    FuncReturnTargets.clear()

    for bp in FuncReturnBPs:
        if not bp.is_valid():
            bp.delete()

    try:
        gdb.execute("clear lj_BC_RET")
        gdb.execute("clear lj_BC_RET0")
        gdb.execute("clear lj_BC_RET1")

    except:
        pass

def removeAllTraceEventBPs():
    for bp in TraceEventBPs:
        if not bp.is_valid():
            bp.delete()

    try:
        gdb.execute("clear lj_trace_log_event")

    except:
        pass

def removeAllBPs():
    removeAllEntryBPs()
    removeAllReturnBPs()
    removeAllTraceEventBPs()

class ldel(gdb.Command):
    """This command deletes existing breakpoints on (interpreted) Lua function call entries and returns
Usage: ldel [spec]"""

    def __init__ (self):
        super (ldel, self).__init__("ldel", gdb.COMMAND_USER)

    src_line_pat = re.compile("(\S+):(\d+)")

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        global FuncEntryMatchAll, FuncEntryBPs, FuncEntryTargets
        global FuncReturnTargets

        if len(argv) == 0:
            # remove all Lua function breakpoints
            removeAllBPs()
            return

        if len(argv) != 1:
            raise gdb.GdbError("usage: ldel [spec]")

        spec = argv[0]
        #out("spec = %s\n" % spec)
        if spec == "*":
            FuncEntryMatchAll = False

        else:
            m = re.match(lb.src_line_pat, spec)
            if m is not None:
                fname = m.group(1)
                lineno = int(m.group(2))

                #if FuncEntryMatchAll:
                    #raise gdb.GdbError("Breakpoint already set on all Lua function entries")

                out("Searching Lua function at %s:%d...\n" % (fname, lineno))
                res = find_lfunc_by_src_loc(fname, lineno)
                found = False
                for hit in res:
                    fn = hit[0]
                    path = hit[1]
                    found = True
                    key = ptr2int(fn)
                    found_bps = False
                    if key in FuncEntryTargets:
                        out("Remove entry breakpoint on (GCfunc*)%#x at %s:%d\n" \
                            % (key, path, lineno))
                        found_bps = True
                        FuncEntryTargets.pop(key, None)
                        if not FuncEntryTargets:
                            removeAllEntryBPs()

                    to_rm = []
                    for key in FuncReturnTargets:
                        rec = FuncReturnTargets[key]
                        if rec[0] == spec or rec[1] == spec:
                            found_bps = True
                            to_rm.append(key)

                    if not found_bps:
                        raise gdb.GdbError("No existing breakpoint set " \
                                           "on (GCfunc*)%#x at %s:%d\n" \
                                           % (key, path, lineno))

                    for key in to_rm:
                        out("Remove return breakpoint on (GCfunc*)%#x at %s:%d\n" \
                            % (key, path, lineno))
                        FuncReturnTargets.pop(key, None)
                        if not FuncReturnTargets:
                            removeAllReturnBPs()

                if not found:
                    raise gdb.GdbError("failed to find Lua function matching %s" \
                            % spec)
            else:
                raise gdb.GdbError("Bad spec: %s" % spec)

ldel()

class linfob(gdb.Command):
    """This command shows all the existing breakpoints on (interpreted) Lua function call entries and returns
Usage: linfob [spec]"""

    def __init__ (self):
        super (linfob, self).__init__("linfob", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 0:
            raise gdb.GdbError("usage: linfob")

        global FuncEntryMatchAll, FuncEntryBPs, FuncEntryTargets

        if not FuncEntryMatchAll and not FuncEntryTargets \
                and not FuncReturnTargets and len(TraceEventBPs) == 0:
            raise gdb.GdbError("No Lua breakpoints.")

        out("Type\tAddress\t\t\tWhat\n")

        if FuncEntryMatchAll:
            out("entry\t-\t*\n")

        for fn in FuncEntryTargets:
            spec = FuncEntryTargets[fn]
            out("entry\t(GCfunc*)%#x\t%s\n" % (fn, spec))

        for pc in FuncReturnTargets:
            rec = FuncReturnTargets[pc]
            spec = rec[0]
            loc = rec[1]
            out("return\t(BCIns*)%#x\t%s in func %s\n" % (pc, spec, loc))

        if len(TraceEventBPs) > 0:
            out("trace\t-\t-\n")

linfob()

FuncReturnTargets = {}
FuncReturnBPs = []

class BCRetBP (gdb.Breakpoint):
    def __init__ (self, frame="lj_BC_RET"):
        super (BCRetBP, self).__init__(frame)

    ret_count = None

    def stop (self):
        RA = gdb.parse_and_eval("$ecx")
        BASE = gdb.parse_and_eval("$edx").cast(typ("TValue*"))
        pc = gdb.parse_and_eval("$ebx").cast(typ("BCIns*")) - 1
        #fntv = BASE[RA]

        #ins = pc.dereference()
        #oidx = int(6 * (ins & 0xff))
        #op = bcnames[oidx:oidx+6]
        #print("op: %s" % op)

        global FuncReturnTargets
        #fn = gcval(fntv)['fn'].address
        key = ptr2int(pc)
        if not key in FuncReturnTargets:
            return False

        rec = FuncReturnTargets[key]

        #dump_tvalue(fntv)
        #pc = gdb.parse_and_eval("$ebx").cast(typ("BCIns*")) - 1
        #locate_pc(pc, False)
        if self.ret_count is None:
            RD = gdb.parse_and_eval("$eax")
            RD -= 1
        else:
            RD = self.ret_count

        out("Return breakpoint hit at\n\t\tline %s of function %s\n" \
            % (rec[1], rec[0]))

        if RD == 0:
            out("No return values.\n")

        else:
            out("Returning %d value(s):\n" % RD)

            for i in xrange(0, RD):
                dump_tvalue(BASE[RA + i], True)
        return True

class BCRet0BP (BCRetBP):
    def __init__ (self):
        super (BCRet0BP, self).__init__("lj_BC_RET0")
        self.ret_count = 0

class BCRet1BP (BCRetBP):
    def __init__ (self):
        super (BCRet1BP, self).__init__("lj_BC_RET1")
        self.ret_count = 1

class lrb(gdb.Command):
    """This command sets a breakpoint on (interpreted) Lua function call returns
Usage: lrb <spec>"""

    def __init__ (self):
        super (lrb, self).__init__("lrb", gdb.COMMAND_USER)

    src_line_pat = re.compile("(\S+):(\d+)")

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 1:
            raise gdb.GdbError("usage: lrb <spec>")

        global FuncReturnTargets, FuncReturnBPs

        spec = argv[0]
        #out("spec = %s\n" % spec)
        m = re.match(lb.src_line_pat, spec)
        if m is not None:
            fname = m.group(1)
            lineno = int(m.group(2))

            out("Searching Lua function at %s:%d...\n" % (fname, lineno))
            res = find_lfunc_by_src_loc(fname, lineno)
            found = False
            for hit in res:
                fn = hit[0]
                path = hit[1]
                #out("Found function (GCfunc*)%#x at %s:%d\n" \
                    #% (ptr2int(fn), path, lineno))

                # find all RET* bytecode PCs:
                pt = funcproto(fn)
                if not pt:
                    raise gdb.GdbError("failed to find the GCproto context")
                startpc = mref(fn['l']['pc'], "BCIns")
                sizebc = pt['sizebc']

                for i in xrange(0, sizebc):
                    ins = startpc[i]
                    oidx = int(6 * (ins & 0xff))
                    op = bcnames[oidx:oidx+6]
                    #print("op: %s" % op)
                    if op == "RET   " or op == "RET0  " or op == "RET1  " \
                            or op == "RETM  ":
                        found = True
                        pc = startpc + i
                        loc = pc2loc(pt, pc)
                        out("Set breakpoint on %s (line %s)\n" % (op.strip(), \
                            loc))
                        FuncReturnTargets[ptr2int(pc)] = (spec, loc)

                if not found:
                    raise gdb.GdbError("failed to find RET* instructions in " \
                                       "the function %s" % spec)

            if not found:
                raise gdb.GdbError("failed to find function matching " \
                                   "%s" % spec)
        else:
            raise gdb.GdbError("Bad spec: %s" % spec)

        if not FuncReturnBPs:
            FuncReturnBPs.append(BCRetBP())
            FuncReturnBPs.append(BCRet0BP())
            FuncReturnBPs.append(BCRet1BP())
            # lj_BC_RETM is already covered by lj_BC_RET

        else:
            # validate the break points to protect against user
            # removal
            for bp in FuncReturnBPs:
                if not bp.is_valid():
                    bp.__init__()

lrb()

class TraceEventBP (gdb.Breakpoint):
    def __init__ (self):
        super (TraceEventBP, self).__init__("lj_trace_log_event")

    def stop (self):
        e = gdb.parse_and_eval("rec")

        if not e:
            raise gdb.GdbError("No event record found")

        event = e["event"]

        traceno = e["traceno"]
        L = e["thread"]
        fn = e["fn"]
        pc = e["ins"]

        pt = pc2proto(pc)

        evname = None
        exitno = None

        #print("trace event type: %d" % rec["event"])
        if event == 0:
            # trace entry
            evname = "==> Enter"

        elif event == 1:
            exitno = e['exitno']
            direct_exit = e["directexit"]
            if direct_exit:
                evname = "<== Direct exit"

            else:
                evname = "<== Normal exit"

        else:
            evname = "*** Start recording"

        out("%s trace #%d: L=%#x pc=%#x\n" \
            % (evname, int(traceno), ptr2int(L), ptr2int(pc)))
        if exitno is not None:
            out("\texit no: %d\n" % int(exitno))
        out("\tline: %s\n" % pc2loc(pt, pc))
        out("\tfunction: %s\n" % fmtfunc(fn))

        if event == 1:  # exit
            out("\tbacktrace:\n")
            gdb.execute("lbt full")

        return True

TraceEventBPs = []

class ltb(gdb.Command):
    """This command sets a breakpoint on (compiled) LuaJIT trace entry and exit.
Usage: ltb"""

    def __init__ (self):
        super (ltb, self).__init__("ltb", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 0:
            raise gdb.GdbError("usage: ltb")

        global TraceEventBPs

        if not TraceEventBPs:
            TraceEventBPs.append(TraceEventBP())

        else:
            # validate the break points to protect against user
            # removal
            for bp in TraceEventBPs:
                if not bp.is_valid():
                    bp.__init__()

ltb()

class ldumpstack(gdb.Command):
    """This command takes a lua_State pointer and dumps all contents from
it's stack.
Usage: ldumpstack (lua_State *)"""

    def __init__ (self):
        super (ldumpstack, self).__init__("ldumpstack", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 1:
            raise gdb.GdbError("1 argument expected!\nusage: ltb <lua_State *>")

        L = gdbutils.parse_ptr(argv[0], "lua_State*")

        top = lua_gettop(L)

        for x in range(top):
            out("index = %d\n" % (x + 1))
            tv = stkindex2adr(L, x + 1)
            gdb.execute("lval 0x%x" % ptr2int(tv))

ldumpstack()
