import gdbutils

globalvar = gdbutils.globalvar
typ = gdbutils.typ

def ngx_cycle_get_module_main_conf(cycle, module_index):
    ngx_http_module = globalvar("ngx_http_module")
    ctx = cycle['conf_ctx'][ngx_http_module['index']].cast(typ("ngx_http_conf_ctx_t*"))
    if not ctx:
        return gdbutils.null()
    return ctx['main_conf'][module_index]

