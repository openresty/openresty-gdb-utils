import gdb
import gdbutils
import ngxlua
import string

typ = gdbutils.typ
null = gdbutils.null
newval = gdbutils.newval
ptr2int = gdbutils.ptr2int
err = gdbutils.err
out = gdbutils.out
warn = gdbutils.warn

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

vmstates = ['Interpreted', 'C code from intperpreted Lua', \
        'Garbage collector', 'Trace exit handler', \
        'Trace recorder', 'Optimizer', 'Assembler']

NO_BCPOS = ~0

FF_LUA = 0
FF_C   = 1

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
        print("cframe pc: [0x%x]" % ptr2int(ins))
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
        print("T: %d" % int(T['traceno']))
        pos = proto_bcpos(pt, mref(T['startpc'], "BCIns"))
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
                    for slot in xrange(1, nf - frame):
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
    return (gl.cast(typ("char*")) - typ("GG_State")['g'].bitpos / 8) \
            .cast(typ("GG_State*"))

def G2J(gl):
    return G2GG(gl)['J'].address

def traceref(J, n):
    return gcref(J['trace'][n]).cast(typ("GCtrace*"))

class lbt(gdb.Command):
    """This command dumps out the current Lua-land backtrace in the lua_State specified. Only LuaJIT 2.1 is supported.
Usage: lbt [L]"""

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
                raise gdb.GdbError("jit base is NULL")
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
            out("Compiled (trace #%d)\n" % vmstate)

        elif ~vmstate >= LJ_VMST__MAX:
            raise gdb.GdbError("Invalid VM state: ", ~vmstate)

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
    """This command prints out the global table.
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
    hmask = t['hmask']
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
            out("(TValue*)0x%x\n" % ptr2int(tv))
            out("type: %s\n" % ltype(tv))
        else:
            raise gdb.GdbError("Key not found.")

        #print "g: ", hex(int(L['glref']['ptr32']))

ltabgets()

def ltype(tv, t):
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

def dump_tvalue(o):
    if tvisudata(o):
        ud = udataV(o)
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

    elif tvisstr(o):
        gcs = strV(o)
        out("\t\tstring: \"%s\" (len %d)\n" % (lstr2str(gcs), int(gcs['len'])))

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
        out("\t\tnumber\n")

    elif tvisnil(o):
        out("\t\tnil\n")

    elif tvistrue(o):
        out("\t\ttrue\n")

    elif tvisfalse(o):
        out("\t\tfalse\n")

    elif tvisfunc(o):
        fn = gcval(o)['fn'].address
        pt = funcproto(fn)
        if pt:
            lineno = pt['firstline']
            #print "proto: 0x%x\n" % ptr2int(pt)
            name = proto_chunkname(pt)
            #print "name: 0x%x\n" % ptr2int(name)
            #print "len: %d\n" % int(name['len'])
            if name:
                try:
                    path = lstr2str(name)
                    out("\t\tLua function (GCfunc*)0x%x at %s:%d\n" \
                            % (ptr2int(fn), path, lineno))
                    return

                except Exception as e:
                    out("ERROR: failed to resolve chunk name: %s\n" % e)

        out("\t\tfunction (0x%x)\n" % ptr2int(o))

    else:
        out("\t\t%s (0x%x)\n" % (ltype(o), ptr2int(o)))

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
            return

        m = re.search(r'TValue', typstr)
        if not m:
            raise gdb.GdbError("TValue * expected, but got %s" % typstr)

        dump_tvalue(o)

lval()

class lproto(gdb.Command):
    """This command prints out all the Lua prototypes (the GCproto* pointers) via the file name and file line number where the function is defined.
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
                        if string.find(path, fname) >= 0:
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

class lfunc(gdb.Command):
    """This command prints out all the Lua functions (the GCfunc* pointers) via the file name and file line number where the function is defined.
Usage: lfunc file lineno"""

    def __init__ (self):
        super (lfunc, self).__init__("lfunc", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) != 2:
            raise gdb.GdbError("Usage: lfunc file lineno")

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
            if o['gch']['gct'] == ~LJ_TFUNC():
                fn = o['fn'].address
                pt = funcproto(fn)
                if pt and pt['firstline'] == lineno:
                    #print "proto: 0x%x\n" % ptr2int(pt)
                    name = proto_chunkname(pt)
                    #print "name: 0x%x\n" % ptr2int(name)
                    #print "len: %d\n" % int(name['len'])
                    if name:
                        path = lstr2str(name)
                        if string.find(path, fname) >= 0:
                            out("Found Lua function (GCfunc*)0x%x at %s:%d\n" \
                                    % (ptr2int(fn), path, lineno))
            p = o['gch']['nextgc'].address

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

def tvisthread(o):
    return itype(o) == LJ_TTHREAD()

def threadV(o):
    # &gcval(o)->th
    return gcval(o)['th'].address

def tabref(r):
    return gcref(r)['tab'].address

class lfenv(gdb.Command):
    """This command prints out all the upvalues in the GCfunc* pointer specified.
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

        if tvisthread(o):
            o = threadV(o)
            tab = tabref(threadV(o['env']))
            out("environment table: (GCtab*)0x%x\n" % ptr2int(tab))

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

class ltrace(gdb.Command):
    """This command prints out all the upvalues in the GCfunc* pointer specified.
Usage: ltrace"""

    def __init__ (self):
        super (ltrace, self).__init__("ltrace", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 1:
            raise gdb.GdbError("usage: ltrace trace-no")

        traceno = int(argv[0])
        L = get_global_L()

        g = G(L)
        J = G2J(g)

        if traceno < 0 or traceno > J['sizetrace']:
            raise gdb.GdbError("bad trace number: %d" % traceno)

        T = traceref(J, traceno)
        out("(GCtrace*)0x%x\n" % ptr2int(T))
        if T:
            szmcode = int(T['szmcode'])
            out("mcode size: %d\n" % szmcode)
            out("mcode start addr: 0x%x\n" % ptr2int(T['mcode']))
            out("mcode end addr: 0x%x\n" % (ptr2int(T['mcode']) + szmcode))
            pt = gcref(T['startpt'])['pt'].address
            pc = proto_bcpos(pt, mref(T['startpc'], "BCIns"))
            line = lj_debug_line(pt, pc)
            name = proto_chunkname(pt)
            if name:
                path = lstr2str(name)
                out("%s:%d\n" % (path, line))

ltrace()

def locate_pc(pc):
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
                    out("source line: %s:%d\n" % (path, line))
                    out("proto first line: %d\n" % int(pt['firstline']))

        p = o['gch']['nextgc'].address

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

        out("pc type: %s\n" % str(pc.type))

        locate_pc(pc)

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

REF_BIAS = 0x8000

irnames = "LT    GE    LE    GT    ULT   UGE   ULE   UGT   EQ    NE    ABC   RETF  NOP   BASE  PVAL  GCSTEPHIOP  LOOP  USE   PHI   RENAMEPROF  KPRI  KINT  KGC   KPTR  KKPTR KNULL KNUM  KINT64KSLOT BNOT  BSWAP BAND  BOR   BXOR  BSHL  BSHR  BSAR  BROL  BROR  ADD   SUB   MUL   DIV   MOD   POW   NEG   ABS   ATAN2 LDEXP MIN   MAX   FPMATHADDOV SUBOV MULOV AREF  HREFK HREF  NEWREFUREFO UREFC FREF  STRREFLREF  ALOAD HLOAD ULOAD FLOAD XLOAD SLOAD VLOAD ASTOREHSTOREUSTOREFSTOREXSTORESNEW  XSNEW TNEW  TDUP  CNEW  CNEWI BUFHDRBUFPUTBUFSTRTBAR  OBAR  XBAR  CONV  TOBIT TOSTR STRTO CALLN CALLA CALLL CALLS CALLXSCARG  "

ircall = ("lj_str_cmp", "lj_str_find", "lj_str_new", "lj_strscan_num", "lj_strfmt_int",
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
)

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

irfield = [ "str.len", "func.env", "func.pc", "thread.env", "tab.meta", "tab.array", "tab.node", "tab.asize", "tab.hmask", "tab.nomm", "udata.meta", "udata.udtype", "udata.file", "cdata.ctypeid", "cdata.ptr", "cdata.int", "cdata.int64", "cdata.int64_4" ]

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

irfpm = ["floor", "ceil", "trunc", "sqrt", "exp", "exp2", "log", "log2", "log10", "sin", "cos", "tan", "other"]

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
        k = re.escape(k).replace("\\_", "_")
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

class lir(gdb.Command):
    """This command prints out all the IR code for the trace specified by its number.
Usage: lir"""

    def __init__ (self):
        super (lir, self).__init__("lir", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 1:
            raise gdb.GdbError("usage: lir trace-no")

        traceno = int(argv[0])
        L = get_global_L()

        g = G(L)
        J = G2J(g)

        if traceno < 0 or traceno > J['sizetrace']:
            raise gdb.GdbError("bad trace number: %d" % traceno)

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
                    out("%04d ------------ LOOP ------------" % ins)
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

