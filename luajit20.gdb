define ltop
    set $L_State = (lua_State *)($arg0)
    set $elems_num = (int)(($L_State->top) - ($L_State->base))
    printf "The number of elements is: %d\n", $elems_num
end

document ltop
    Print the num of elems by given Lua State
    Usage: ltop addr
end

define lvalue
    while (1)
        set $lvalue_TValue = (TValue *)($arg0)
        if ($lvalue_TValue.it == ~0u)
            printf "nil"
            loop_break
        end

        if ($lvalue_TValue.it == ~1u)
            printf "false"
            loop_break
        end

        if ($lvalue_TValue.it == ~2u)
            printf "true"
            loop_break
        end

        if ($lvalue_TValue.it == ~3u)
            printf "<lightudata: 0x%x>", (int)$lvalue_TValue
            loop_break
        end

        if (((int32_t)($lvalue_TValue->it) >> 15) == -2)
            printf "<lightudata: 0x%x>", (int)$lvalue_TValue
            loop_break
        end

        if ($lvalue_TValue.it == ~4u)
            set $str_res = (char *)(&(((GCobj *)($lvalue_TValue.gcr.gcptr32))->str)+1)
            printf "\"%s\"", $str_res
            loop_break
        end

        if ($lvalue_TValue.it == ~5u)
            printf "..."
            loop_break
        end

        if ($lvalue_TValue.it == ~6u)
            printf "<thread: 0x%x>", (int)$lvalue_TValue
            loop_break
        end

        if ($lvalue_TValue.it == ~7u)
            printf "..."
            loop_break
        end

        if ($lvalue_TValue.it == ~8u)
            printf "<func: 0x%x>", (int)$lvalue_TValue
            loop_break
        end

        if ($lvalue_TValue.it == ~9u)
            printf "..."
            loop_break
        end

        if ($lvalue_TValue.it == ~10u)
            printf "<cdata: 0x%x>", (int)$lvalue_TValue
            loop_break
        end

        if ($lvalue_TValue.it == ~11u)
            printf "<0x%x>", (int)$lvalue_TValue
            ltab $lvalue_TValue
            loop_break
        end

        if ($lvalue_TValue.it == ~12u)
            printf "<udata: 0x%x>", (int)$lvalue_TValue
            loop_break
        end

        if ($lvalue_TValue.it < ~13u)
            set $num_res = (int32_t) $lvalue_TValue.n
            printf "%d", $num_res
            loop_break
        end

        printf "Value Error!"
        loop_break
    end
end

document lvalue
    Print the raw value of given TValue
    Usage: ltop addr
end

define ltype
    set $ltype_TValue = (TValue *)($arg0)
    while (1)
        if ($ltype_TValue->it == ~0u)
            printf "nil: "
            loop_break
        end

        if ($ltype_TValue->it == ~1u)
            printf "bool: "
            loop_break
        end

        if ($ltype_TValue->it == ~2u)
            printf "bool: "
            loop_break
        end

        if ($ltype_TValue->it == ~3u)
            printf "lightudata: "
            loop_break
        end

        if (((int32_t)($ltype_TValue->it) >> 15) == -2)
            printf "lightudata: "
            loop_break
        end

        if ($ltype_TValue->it == ~4u)
            printf "str: "
            loop_break
        end

        if ($ltype_TValue->it == ~5u)
            printf "upval: "
            loop_break
        end

        if ($ltype_TValue->it == ~6u)
            printf "thread: "
            loop_break
        end

        if ($ltype_TValue->it == ~7u)
            printf "proto: "
            loop_break
        end

        if ($ltype_TValue->it == ~8u)
            printf "func: "
            loop_break
        end

        if ($ltype_TValue->it == ~9u)
            printf "trace: "
            loop_break
        end

        if ($ltype_TValue->it == ~10u)
            printf "cdata: "
            loop_break
        end

        if ($ltype_TValue->it == ~11u)
            printf "tab: "
            loop_break
        end

        if ($ltype_TValue->it == ~12u)
            printf "udata: "
            loop_break
        end

        if ($ltype_TValue->it < ~13u)
            printf "num: "
            loop_break
        end

        printf "Type Error!"
        loop_break
    end
end

document ltype
    Print the type of given TValue
    Usage: ltype addr
end


define lreg
    set $lreg_L = (lua_State *)($arg0)
    set $lreg_key = $arg1
    set $lreg_global_state = (global_State *)($lreg_L->glref->ptr32)
    set $lreg_reg_tab = (((GCobj *)($lreg_global_state.registrytv->gcr->gcptr32))->tab)
    set $lreg_hmask = $lreg_reg_tab.hmask
    set $lreg_i = 0
    set $lreg_node = (Node *)($lreg_reg_tab.node.ptr32)
    set $lreg_found = 0
    while ($lreg_i <= $lreg_hmask)
        if ($lreg_node[$lreg_i].val.it != ~0u)
            if ($lreg_node[$lreg_i].key.gcr.gcptr32 == $lreg_key)
                lvalue &$lreg_node[$lreg_i].val
                printf "\n"
                set $lreg_found = 1
                loop_break
            end
        end
        set $lreg_i++
    end

    if ($lreg_found != 1)
        printf "nothing found!\n"
    end

end

document lreg
    Print the value by given key in Lua registry
    Usage: lreg lua-state-addr udata-key-addr
end

define lfullstack
    set $L = (lua_State *)($arg0)
    set $elems_num = (int)(($L->top) - ($L->base))
    set $idx = 0
    while ( $idx != $elems_num)
        set $tvalue = $L->base + $idx
        printf "%d: ", $idx+1
        ltype $tvalue
        lvalue $tvalue
        set $idx++
        printf "\n"
    end
    if ($elems_num == 0)
        printf "stack empty"
    end
    printf "\n"
end

document lfullstack
    Print all the elems of given Lua State
    Usage: lfullstack addr
end

define lgc
    set $lgc_L = (lua_State *)($arg0)
    set $lgc_global_state = (global_State *)($lgc_L->glref->ptr32)
    set $lgc_gc = $lgc_global_state.gc
    printf "GC memory currently allocated: %d\n", $lgc_gc.total
end

document lgc
    Print Lua garbage collection info of given Lua State
    Usage: lfullstack addr
end
# vi:set ft=gdb ts=4 sw=4 et fdm=marker:
