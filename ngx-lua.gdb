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

define ngx-lua-main-conf
    set $r = (ngx_http_request_t *) $arg0
    set $main_conf = (ngx_http_lua_main_conf_t *) $r->main_conf[ngx_http_lua_module.ctx_index]

    printf "lua main VM: %p\n", $main_conf->lua

    printf "pending timers: %d (max=%d)\n", $main_conf->pending_timers, \
           $main_conf->max_pending_timers

    printf "running timers: %d (max=%d)\n", $main_conf->running_timers, \
           $main_conf->max_running_timers

    printf "regex cache entries: %d (max=%d)\n", \
           $main_conf->regex_cache_entries, \
           $main_conf->regex_cache_max_entries

    printf "regex match limit: %d\n", $main_conf->regex_match_limit
end

define ngx-lua-thread
    set $coctx = (ngx_http_lua_co_ctx_t *) $arg0
    echo $arg1
    printf " thread is %p, L=%p, ref=%d, status: %s\n", \
           $coctx, $coctx->co, $coctx->co_ref, \
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

define visit-timer-node
    set $index = 1
    eval "set $stack_%d = (ngx_rbtree_node_t *) $arg0", $index

    while $index > 0
        eval "set $temp = $stack_%d", $index
        set $index = $index - 1

        if $temp != $sentinel
            set $ev = (ngx_event_t *) ((char *) $temp - (int) &((ngx_event_t *) 0)->timer)
            set $is_lua_timer = $ev->handler == ngx_http_lua_timer_handler

            printf "timer node key=%lu, is_lua_timer=%d, in %d msec\n", \
                   $temp->key, \
                   $ev->handler == ngx_http_lua_timer_handler, \
                   $temp->key - ngx_current_msec

            if $is_lua_timer
                set $tctx = (ngx_http_lua_timer_ctx_t *) $ev->data
                printf "coroutine=%p. stack contents:\n", $tctx->co

                ldumpstack $tctx->co
            end

            printf "\n"

            set $index = $index + 1
            eval "set $stack_%d = $temp->left", $index

            set $index = $index + 1
            eval "set $stack_%d = $temp->right", $index
        end
    end
end

define dump-all-timers
    set $sentinel = ngx_event_timer_rbtree.sentinel
    set $root = ngx_event_timer_rbtree.root

    printf "now is %lu\n\n", ngx_current_msec

    if $sentinel != $root
        visit-timer-node $root $sentinel
    else
        printf "timer tree empty\n"
    end
end
