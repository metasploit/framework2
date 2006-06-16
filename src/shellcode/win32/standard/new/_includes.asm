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

  ; No sanity checks.
  %macro INET_ADDR 2
    %define IP  %2
    %strlen IP_LEN  IP
    %assign i  IP_LEN-1
    %assign ATOISUM  0

    %rep IP_LEN
      %substr ATOICHAR  IP i

      %if ATOICHAR == '.' || i == 0
; <ghetto atoi>
        %substr ATOICHAR  IP i+1

        %assign ATOINUM  (ATOICHAR - '0')
        %substr ATOICHAR  IP i+2
        %if  i+2 <= IP_LEN && ATOICHAR != '.'
          %assign ATOINUM  (ATOINUM * 10) + ATOICHAR - '0'
          %substr ATOICHAR  IP i+3
          %if i+3 <= IP_LEN && ATOICHAR
            %assign ATOINUM  (ATOINUM * 10) + ATOICHAR - '0'
          %endif
        %endif

        %assign ATOISUM  (ATOISUM * 256) + ATOINUM
; </ghetto atoi>
      %endif

      %assign i i-1
    %endrep

    %1 ATOISUM
  %endmacro
%endif
