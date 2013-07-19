set $LUA_NOREF = -2

define ngx-lua-code-cache
    set $r = (ngx_http_request_t *) $arg0
    set $loc_conf = (ngx_http_lua_loc_conf_t *) $r->loc_conf[ngx_http_lua_module.ctx_index]
    if $loc_conf->enable_code_cache == 0
        print "lua code cache off"
    else
        print "lua code cache on"
    end
end

define ngx-lua-thread
    set $coctx = (ngx_http_lua_co_ctx_t *) $arg0
    echo $arg1
    printf " thread is %p, L=%p, status: %s\n", \
           $coctx, $coctx->co, \
           ngx_http_lua_co_status_names[$coctx->co_status]
end

define ngx-lua-uthreads
    set $r = (ngx_http_request_t *) $arg0
    set $ctx = (ngx_http_lua_ctx_t *) $r->ctx[ngx_http_lua_module.ctx_index]
    if $ctx->on_abort_co_ctx
        printf "it has an on_abort thread %p\n", $ctx->on_abort_co_ctx
    end
    set $entry_co_ctx = &($ctx->entry_co_ctx)
    if $entry_co_ctx->co_ref != $LUA_NOREF
        ngx-lua-thread $entry_co_ctx entry
    end
    printf "there are %d user threads.\n", $ctx->uthreads
    if $ctx->flushing_coros
        printf "there are %d coroutines waiting on ngx.flush.\n",
               $ctx->flushing_coros
    end

    set $part = &$ctx->user_co_ctx->part
    set $cc = (ngx_http_lua_co_ctx_t *) $part->elts
    set $n = 0
    set $i = 0
    while 1
        if $i >= $part->nelts
            if !$part->next
                loop_break
            end

            set $part = $part->next
            set $cc = (ngx_http_lua_co_ctx_t *) $part->elts
            set $i = 0
        end
        set $i++
        set $ref = $cc[$i].co_ref
        if $ref != $LUA_NOREF
            set $n++
            printf "#%d ", $n
            ngx-lua-thread &$cc[$i] user
        end
    end
    printf "Found %d user threads.\n", $n

    if $ctx->exited
        printf "request already exited with code %d.\n", $ctx->exit_code
    end
end
