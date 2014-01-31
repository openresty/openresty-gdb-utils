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
CFRAME_OFS_PC = 412

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
    return mref((cf.cast(typ("char*")) + CFRAME_OFS_PC).cast(typ("MRef*")), \
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
    return 0

def debug_framepc(L, T, fn, pt, nextframe):
    if not isluafunc(fn):
        return NO_BCPOS
    if not nextframe:
        cf = cframe_raw(L['cframe'])
        if not cf or cframe_pc(cf) == cframe_L(cf):
            return NO_BCPOS
        ins = cframe_pc(cf)
    else:
        if frame_islua(nextframe):
            ins = frame_pc(nextframe)
        elif frame_iscont(nextframe):
            ins = frame_contpc(nextframe)
        else:
            warn("Lua function below errfunc/gc/hook not supported yet")
            return NO_BCPOS
    pos = proto_bcpos(pt, ins) - 1
    if pos > pt['sizebc']:
        if not T:
            # TODO
            #T = ((ins - 1).cast(typ("char*")) - \
                    #typ("GCtrace")['startins'].bitpos / 8).cast(typ("GCtrace*"))
            return NO_BCPOS
        pos = proto_bcpos(pt, mref(T['startpc'], "BCIns"))
    return pos

def debug_frameline(L, T, fn, pt, nextframe):
    pc = debug_framepc(L, T, fn, pt, nextframe)
    if pc != NO_BCPOS:
        pt = funcproto(fn)
        return lj_debug_line(pt, pc)
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

def lj_debug_dumpstack(L, T, depth, base):
    global cfunc_cache

    level = 0
    dir = 1
    if depth < 0:
        level = ~depth
        depth = dir = -1

    bot = tvref(L['stack'])
    bt = ""
    while level != depth:
        #print "checking level: %d" % level

        frame, size = lj_debug_frame(L, base, level, bot)

        if frame:
            nextframe = (frame + size) if size else null()
            fn = frame_func(frame)
            #print "type(fn) == %s" % fn.type
            if not fn:
                return ""

            if isluafunc(fn):
                pt = funcproto(fn)
                line = debug_frameline(L, T, fn, pt, nextframe)
                if line < 0:
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
        if len(argv) > 1:
            raise gdb.GdbError("Usage: lbt [L]")

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
            bt = lj_debug_dumpstack(L, T, 30, base)

        else:
            if vmstate == ~LJ_VMST_EXIT:
                base = tvref(g['jit_base'])
                if base:
                    bt = lj_debug_dumpstack(L, 0, 30, base)

                else:
                    base = L['base']
                    bt = lj_debug_dumpstack(L, 0, 30, base)

            else:
                if vmstate == ~LJ_VMST_INTERP and not L['cframe']:
                    out("No Lua code running.\n")
                    return

                if vmstate == ~LJ_VMST_INTERP or \
                       vmstate == ~LJ_VMST_C or \
                       vmstate == ~LJ_VMST_GC:
                    base = L['base']
                    bt = lj_debug_dumpstack(L, 0, 30, base)

                else:
                    out("No Lua code running.\n")
                    return
        if not bt:
            out("Empty backtrace.\n")
        out(bt)

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

def tvisstr(o):
    return itype(o) == LJ_TSTR()

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

def ltype(tv):
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
        return "func"

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

        if typstr != "TValue *":
            raise gdb.GdbError("TValue * expected")

        if tvisudata(o):
            ud = udataV(o)
            t = ud['udtype']
            out("udata type: %s\n" % udata_types[int(t)])
            out("      payload len: %d\n" % int(ud['len']))
            out("      payload ptr: 0x%x\n" % ptr2int(ud + 1))
            if int(t) == UDTYPE_FFI_CLIB:
                cl = uddata(ud).cast(typ("CLibrary*"))
                out("      CLibrary handle: (void*)0x%x\n" % \
                        ptr2int(cl['handle']))
                out("      CLibrary cache: (GCtab*)0x%x\n" \
                        % ptr2int(cl['cache']))

        elif tvisstr(o):
            gcs = strV(o)
            out("string: \"%s\" (len %d)" % (lstr2str(gcs), int(gcs['len'])))

        elif tviscdata(o):
            cts = ctype_cts(mL)
            cd = cdataV(o)
            ptr = cdataptr(cd)
            out("type cdata\n")
            out("\tcdata object: (GCcdata*)0x%x\n" % ptr2int(cd))
            out("\tcdata value pointer: (void*)0x%x\n" % ptr2int(ptr))
            d = ctype_get(cts, cd['ctypeid'])
            out("\tctype object: (CType*)0x%x\n" % ptr2int(d))
            out("\tctype size: %d byte(s)\n" % int(d['size']))
            t = int(ctype_type(d['info']))
            #print "ctype type %d\n" % t
            if ctype_names[t]:
                out("\tctype type: %s\n" % ctype_names[t])
            else:
                err("\tunknown ctype type: %d\n" % t)
            s = strref(d['name'])
            if s:
                out("\tctype element name: %s\n" % lstr2str(s))

        elif tvislightud(o):
            out("light user data: (void*)0x%x\n" % ptr2int(gcrefp(o['gcr'], 'void')))
            return

        else:
            out("type: %s\n" % ltype(o))
            out("TODO")

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

        if traceno < 0:
            raise gdb.GdbError("bad trace number")

        g = G(L)
        J = G2J(g)
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

class lpc(gdb.Command):
    """This command prints out the source line position for the current pc.
Usage: lpc pc pt"""

    def __init__ (self):
        super (lpc, self).__init__("lpc", gdb.COMMAND_USER)

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 2:
            raise gdb.GdbError("usage: lpc pc pt")

        pc = gdbutils.parse_ptr(argv[0], "BCIns*")
        pt = gdbutils.parse_ptr(argv[1], "GCproto*")

        out("pc type: %s\n" % str(pc.type))
        out("pt type: %s\n" % str(pt.type))

        line = lj_debug_line(pt, pc)
        name = proto_chunkname(pt)
        if name:
            path = lstr2str(name)
            out("%s:%d\n" % (path, line))

lpc()

