#!/usr/bin/perl
###############

##
#         Name: HandlerConsole.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::HandlerConsole;
use base 'Msf::HandlerCLI';
use IO::Socket;
use IO::Select;
use POSIX;
use Pex;

use strict;
