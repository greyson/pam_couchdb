/* pam_couchdb module */

/*
 * Written by Greyson Fischer <greyson@foosoft.us> 2012/01/01
 */

#include "curl.hpp"

#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/_pam_macros.h>

extern "C"
{
   PAM_EXTERN int pam_sm_authenticate( pam_handle_t *, int, int, char const ** );
   PAM_EXTERN int pam_sm_setcred( pam_handle_t *, int, int, char const ** );
}
/**
 * Overwrite possibly sensitive memory before free-ing it.
 *
 * @param  xx String containing possibly sensitive information
 * @retval Always NULL (useful for reseting pointer in the same line)
 */
static char * _pam_delete( register char * xx )
{
   _pam_overwrite( xx );
   _pam_drop( xx );
   return NULL;
}

static int converse( pam_handle_t * pamh,
                     struct pam_message ** message,
                     struct pam_response ** response )
{
   int retval;
   void const * void_conv;
   struct pam_conv const * conv;

   retval = pam_get_item( pamh, PAM_CONV, & void_conv );
   conv = (struct pam_conv const *) void_conv;

   if( retval == PAM_SUCCESS )
   {
      retval = conv->conv( 1, (struct pam_message const **) message,
                           response, conv->appdata_ptr );
   }

   return retval;
}

#define CPAMARG_USEFIRSTPASS  0x02

static int _pam_parse( int argc, char const ** argv )
{
   int ctrl;

   for( ctrl = 0; argc-- > 0; ++argv )
   {
      // Check binary arguments
      if( ! strcmp( *argv, "use_first_pass" ) )
         ctrl |= CPAMARG_USEFIRSTPASS;
   }

   return ctrl;
}

static int conversation( pam_handle_t * pamh )
{
   struct pam_message msg[2], *pmsg[2];
   struct pam_response * resp;

   int retval;
   char * token = NULL;

   pmsg[0] = &msg[0];
   msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
   msg[0].msg = "Password: ";

   // Call the conversation expecting 1 response
   resp = NULL;
   retval = converse( pamh, pmsg, &resp );

   if( resp != NULL )
   {
      void const * item;

      // interpret the response
      if( retval == PAM_SUCCESS )
      {
         token = x_strdup( resp[0].resp );
         if( token == NULL )
         {
            return PAM_AUTHTOK_RECOVER_ERR;
         }
      }

      // Set the auth token
      retval = pam_set_item( pamh, PAM_AUTHTOK, token );
      token = _pam_delete( token );
      if( retval != PAM_SUCCESS ||
          (retval = pam_get_item( pamh, PAM_AUTHTOK, & item )) != PAM_SUCCESS )
      {
         return retval;
      }

      _pam_drop_reply( resp, 1 );
   }
   else if( retval == PAM_SUCCESS )
   {
      retval = PAM_AUTHTOK_RECOVER_ERR;
   }

   return retval;
}

int pam_sm_authenticate( pam_handle_t * pamh,
                         int flags,
                         int argc, char const ** argv )
{
   int retval = PAM_AUTH_ERR;
   char const * username = NULL;
   char const * password = NULL;

   // Parse arguments
   int argmask = _pam_parse( argc, argv );

   // Get the username
   retval = pam_get_user( pamh, &username, NULL );
   if( (retval != PAM_SUCCESS) || (!username) )
   {
      return PAM_SERVICE_ERR;
   }

   // If we've been told to use the first pass, we don't converse with
   // the user for a password.
   if( ! argmask & CPAMARG_USEFIRSTPASS )
   {
      // Converse just to be sure we have a password
      retval = conversation( pamh );
      if( retval != PAM_SUCCESS )
      {
         return PAM_CONV_ERR;
      }
   }

   // Check if we got a password.  If use_authtok wasn't specified,
   // then we've already asked once and needn't do so again.
   retval = pam_get_item( pamh, PAM_AUTHTOK, (void const **) & password );
   if( retval != PAM_SUCCESS )
   {
      return -2;
   }

   Curl curl;
   if( username != NULL && password != NULL &&
       curl.checkAuthorized( username, password ) )
   {
      return PAM_SUCCESS;
   }
   else
   {
      return PAM_AUTH_ERR;
   }

   return PAM_USER_UNKNOWN;
}

int pam_sm_setcred( pam_handle_t * pamh, int flags,
                    int argc, char const ** argv )
{
   return PAM_SUCCESS;
}

/*
 * Copyright (c) Greyson Fischer <greyson@foosoft.us>, 2012 All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED `AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
