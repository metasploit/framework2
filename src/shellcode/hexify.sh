#!/bin/sh
#
# You love the ghettoness!
#
# Shellcode that wants to be hexified should have a __BEGIN__ symbol 
# before the first instruction of the payload and an __END__ symbol after
# the last instruction of the payload.  This is what hexify.sh will
# key off of when converting.
#
# hexify.sh [binary]
#

objdump -d $1 | perl -e 'my $on = 2; while (<STDIN>) { $on = 1 if ($on==2 and $_ =~ /__BEGIN__/); $on = 0 if ($_ =~ /__END__/); print $_ if ($on == 1); }' | cut -f 2 | egrep -v "^$|:" | xargs | sed -e 's/ /\\x/g' | perl -e 'print "\\x" . <STDIN>;' | perl -e 'while (sysread(STDIN, $buf, 80)) { chomp $buf; print "\"$buf\"\n"; }'

