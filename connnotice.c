/*
 * connnotice.c - Connection notice feature for Bahamut IRCD
 *
 * Notifies opers about client connections.
 *
 * Author: reverse.dev
 */

#define BIRCMODULE 1
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "channel.h"
#include "hash.h"
#include "hooks.h"
#include "h.h"
#include "structfunc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#define stricmp strcasecmp
#endif

static void *opaque;

/* Forward declaration */
static int connnotice_postaccess(aClient *cptr);

/*
 * This function runs after a client passes the connection (post-access) stage.
 * It sends a notice to all IRC operators when a client connects.
 */
static int connnotice_postaccess(aClient *cptr)
{
    aClient *acptr;
    const char *connect_type;

    if (!cptr->user || cptr->serv)
        return 0;

    if (cptr->from == &me)
        connect_type = "LOCALCONNECT";
    else
        connect_type = "REMOTECONNECT";

    for (acptr = client; acptr; acptr = acptr->next)
    {
        if (IsOper(acptr) && !IsMe(acptr))
        {
            sendto_one(acptr,
                ":%s NOTICE %s :*** -server.dev- *** %s: Client connecting at mars.t-chat.fr: %s!%s@%s (%s)",
                me.name, acptr->name,
                connect_type,
                cptr->name,
                cptr->user->username,
                cptr->user->host,
                cptr->sockhost);
        }
    }

    return 0;
}

/* Required module entry points */
void bircmodule_check(int *ver)
{
    *ver = MODULE_INTERFACE_VERSION;
}

int bircmodule_init(void *real_opaque)
{
    opaque = real_opaque;

    if (!bircmodule_add_hook(CHOOK_POSTACCESS, opaque, connnotice_postaccess))
        return -1;

    sendto_ops("connnotice: loaded (Connection notice active)");
    return 0;
}

void bircmodule_shutdown(void)
{
    bircmodule_del_hook(CHOOK_POSTACCESS, opaque, connnotice_postaccess);
    sendto_ops("connnotice: unloaded");
}

int bircmodule_command(aClient *sptr, int parc, char *parv[])
{
    return 0;
}

int bircmodule_globalcommand(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    return 0;
}

void bircmodule_getinfo(char **version, char **desc)
{
    *version = "1.0";
    *desc = "Connection notice module for Bahamut IRCd";
}
