/*
 * Copyright (c) 2004-2005 vlad902 <vlad902 [at] gmail.com>
 * This file is part of the Metasploit Framework.
 * $Revision$
 */

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>

#include "cmd.h"


void cmd_kill(int argc, char * argv[])
{
	int killsig = 9;

	if(argc > 1)
		killsig = atoi(argv[2]);

	if(kill(atoi(argv[1]), killsig) == -1)
		perror("kill");
}

void cmd_getpid(int argc, char * argv[])
{
	printf("%i\n", getpid());
}

void cmd_getppid(int argc, char * argv[])
{
	printf("%i\n", getppid());
}
