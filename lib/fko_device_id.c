/**
 * \file lib/fko_device_id.c
 *
 * \brief Set/Get/Validate the optional SPA device_id field (protocol v4).
 */

/*  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *****************************************************************************
*/
#include "fko_common.h"
#include "fko.h"

/* Validate a device_id string: printable ASCII, within size limit,
 * and free of characters that would break the colon-delimited SPA
 * field layout (the device_id is base64-encoded onto the wire, so
 * this is just a defense-in-depth check on the plaintext form).
*/
int
validate_device_id(const char *device_id)
{
    int i, len;

    if(device_id == NULL)
        return(FKO_ERROR_INVALID_DATA);

    len = strnlen(device_id, MAX_SPA_DEVICE_ID_SIZE);

    if(len == 0 || len >= MAX_SPA_DEVICE_ID_SIZE)
        return(FKO_ERROR_INVALID_DATA);

    for(i=0; i < len; i++)
    {
        if(isprint((int)(unsigned char)device_id[i]) == 0)
            return(FKO_ERROR_INVALID_DATA);

        /* Reject the SPA field separator and whitespace outright
        */
        if(device_id[i] == ':' || isspace((int)(unsigned char)device_id[i]))
            return(FKO_ERROR_INVALID_DATA);
    }

    return(FKO_SUCCESS);
}

/* Set the SPA device_id data (protocol v4)
*/
int
fko_set_device_id(fko_ctx_t ctx, const char * const device_id)
{
#if HAVE_LIBFIU
    fiu_return_on("fko_set_device_id_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* Context must be initialized.
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* A NULL or empty device_id clears the field.
    */
    if(device_id == NULL
            || strnlen(device_id, MAX_SPA_DEVICE_ID_SIZE) == 0)
    {
        if(ctx->device_id != NULL)
        {
            free(ctx->device_id);
            ctx->device_id = NULL;
            ctx->state |= FKO_DATA_MODIFIED;
        }
        return(FKO_SUCCESS);
    }

    if(strnlen(device_id, MAX_SPA_DEVICE_ID_SIZE) >= MAX_SPA_DEVICE_ID_SIZE)
        return(FKO_ERROR_INVALID_DATA_DEVICEID_TOOBIG);

    if(validate_device_id(device_id) != FKO_SUCCESS)
        return(FKO_ERROR_INVALID_DATA);

    /* Just in case this is a subsequent call to this function.  We
     * do not want to be leaking memory.
    */
    if(ctx->device_id != NULL)
        free(ctx->device_id);

    ctx->device_id = strdup(device_id);

    ctx->state |= FKO_DATA_MODIFIED;

    if(ctx->device_id == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    return(FKO_SUCCESS);
}

/* Return the SPA device_id data.
*/
int
fko_get_device_id(fko_ctx_t ctx, char **device_id)
{
#if HAVE_LIBFIU
    fiu_return_on("fko_get_device_id_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(device_id == NULL)
        return(FKO_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("fko_get_device_id_val", FKO_ERROR_INVALID_DATA);
#endif

    *device_id = ctx->device_id;

    return(FKO_SUCCESS);
}

/***EOF***/
