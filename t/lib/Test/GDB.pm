# Copyright (C) Yichun Zhang (agentzh)

package Test::GDB;

use Cwd qw( cwd );
use Test::Base -Base;
use POSIX ();
use IPC::Run ();

our @EXPORT = qw( run_tests );

my $cwd = cwd();

sub run_tests () {
    for my $block (Test::Base::blocks()) {
        run_test($block);
    }
}

sub bail_out (@) {
    Test::More::BAIL_OUT(@_);
}

sub parse_cmd ($) {
    my $cmd = shift;
    my @cmd;
    while (1) {
        if ($cmd =~ /\G\s*"(.*?)"/gmsc) {
            push @cmd, $1;

        } elsif ($cmd =~ /\G\s*'(.*?)'/gmsc) {
            push @cmd, $1;

        } elsif ($cmd =~ /\G\s*(\S+)/gmsc) {
            push @cmd, $1;

        } else {
            last;
        }
    }
    return @cmd;
}

sub run_test ($) {
    my $block = shift;
    my $name = $block->name;

    my $timeout = $block->timeout() || 10;
    my $opts = $block->opts;
    my $args = $block->args;

    my $cmd = "gdb";

    if (defined $opts) {
        chomp $opts;
        $cmd .= " $opts";
    }

    my $gdbfile;
    my $gdbsrc = $block->gdb;
    if (defined $gdbsrc) {
        $gdbfile = "a.gdb";
        open my $out, ">$gdbfile" or
            bail_out("cannot open $gdbfile for writing: $!");
        print $out ($gdbsrc);
        close $out;
        $cmd .= qq{ -iex 'py import sys; sys.path.insert(1, "$cwd")'}
                . " -iex 'directory $cwd' -iex 'source luajit21.py'"
                . " --quiet --batch -x $gdbfile -ex quit"
    }

    my $luafile;
    if (defined $block->lua) {
        $luafile = "a.lua";
        open my $out, ">$luafile" or
            bail_out("cannot open $luafile for writing: $!");
        print $out ($block->lua);
        close $out;
        $cmd .= " --args luajit $luafile"
    }

    if (defined $args) {
        $cmd .= " $args";
    }

    #warn "CMD: $cmd\n";

    my @cmd = parse_cmd($cmd);

    my ($out, $err);

    eval {
        IPC::Run::run(\@cmd, \undef, \$out, \$err,
                      IPC::Run::timeout($timeout));
    };
    if ($@) {
        # timed out
        if ($@ =~ /timeout/) {
            if (!defined $block->expect_timeout) {
                fail("$name: gdb process timed out");
            }
	} else {
            fail("$name: failed to run command [$cmd]: $@");
        }
    }

    my $ret = ($? >> 8);

    if (defined $luafile) {
        unlink $luafile;
    }

    if (defined $gdbfile) {
        unlink $gdbfile;
    }

    if (defined $block->out) {
        is $out, $block->out, "$name - stdout eq okay";
    }

    my $regex = $block->out_like;
    if (defined $regex) {
        #use re 'debugcolor';
        if (!ref $regex) {
            $regex = qr/$regex/s;
        }
        like $out, $regex, "$name - stdout like okay";
    }

    if (defined $block->err) {
        is $err, $block->err, "$name - stderr eq okay";
    }

    $regex = $block->err_like;
    if (defined $regex) {
        if (!ref $regex) {
            $regex = qr/$regex/s;
        }
        like $err, $regex, "$name - stderr like okay";
    }

    my $exp_ret = $block->ret;
    if (!defined $exp_ret) {
        $exp_ret = 0;
    }
    is $ret, $exp_ret, "$name - exit code okay";
}

1;
# vi: et
