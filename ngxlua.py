import gdbutils
import nginx

null = gdbutils.null
globalvar = gdbutils.globalvar
typ = gdbutils.typ

def ngx_lua_cycle_get_main_conf(cycle):
    index = globalvar("ngx_http_lua_module")['ctx_index']
    #print "ngx_lua module index: %d" % int(index)
    return nginx.ngx_cycle_get_module_main_conf(cycle, index)

def ngx_lua_get_main_lua_vm(cycle):
    lmcf = ngx_lua_cycle_get_main_conf(cycle)
    if lmcf:
        return lmcf.cast(typ("ngx_http_lua_main_conf_t*"))['lua']
    #print "No lmcf found"
    return null()

