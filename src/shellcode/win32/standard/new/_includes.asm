BITS 32

%ifndef __INCLUDES
  %define __INCLUDES 1
  %include "_hash.asm"

  %macro DIRECTION_CLD 0
    %ifndef DIRECTION
      %define DIRECTION 1 ; presume it's std...
    %endif
    %if DIRECTION != 0
      %define DIRECTION 0
      cld
    %endif
  %endmacro

  %macro DIRECTION_STD 0
    %ifndef DIRECTION
      %define DIRECTION 0 ; presume it's cld...
    %endif
    %if DIRECTION != 1
      %define DIRECTION 1
      std
    %endif
  %endmacro

%endif
