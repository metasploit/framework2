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
# $Id$

import inlineegg

class WindowsSyscall(inlineegg.StackBasedSyscall):
    microClass = inlineegg.Microx86
    STDCALL = 0
    CCALL   = 1

    translation = {
        # we need 1 to 1 args mapping for the simple translation to work
        # we'll do better translation in the future
        'exit':('kernel32.dll','ExitProcess',STDCALL),
        'open':('msvcrt.dll','_open',CCALL),
        'read':('msvcrt.dll','_read',CCALL),
        'write':('msvcrt.dll','_write',CCALL),
        'close':('msvcrt.dll','_close',CCALL)
    }
    def __init__(self, micro, LoadLibrary = 0, GetProcAddress = 0):
        inlineegg.StackBasedSyscall.__init__(self, micro)
        self.names={}

    def remember(self, name, addr):
        code, var = self.micro.save(addr)
        self.names[name] = var
        return code

    def resolveDll(self, dllName):
        # print "resolving %s" % dllName
        code, addr = self.syscall('kernel32.dll','LoadLibrary', (dllName,))
        code += self.remember(dllName, addr)
        return code, addr

    def resolveFunction(self, dllName, functionName):
        # print "resolving %s.%s" % (dllName, functionName)
        if not self.names.has_key(dllName):
            code, addr = self.resolveDll(dllName)
        else:
            code, addr = ('', self.names[dllName])

        more_code, addr = self.syscall('kernel32.dll','GetProcAddress',(addr, functionName,))
        code += more_code
        code += self.remember("%s.%s" % (dllName, functionName), addr)
        return code, addr
        
    def resolve(self, dllName, functionName):
        if not self.names.has_key(dllName):
            code, addr = self.resolveDLL(dllName)
        
    def syscall(self, dllName, functionName, args, callingConvention = STDCALL):
        # print "calling %s.%s" % (dllName, functionName)
        if not self.names.has_key("%s.%s" % (dllName, functionName)):
            code, addr = self.resolveFunction(dllName, functionName)
        else:
            code, addr = ('', self.names["%s.%s" % (dllName, functionName)])

        code += self.setArgs(args,notForTemps = (addr,))
        code += self.micro.call(addr)
        if callingConvention == self.STDCALL:
            self.micro.unpush(len(args))

        return code, self.answer()

    def call(self, function, args):
        dll, function, callingConvention = self.translation[function]
        return self.syscall(dll,function,args, callingConvention)
