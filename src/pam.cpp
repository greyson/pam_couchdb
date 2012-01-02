#define PAM_SM_AUTH

#include "curl.hpp"
#include <security/pam_modules.h>
#include <security/_pam_macros.h>

extern "C"
{
   PAM_EXTERN int pam_sm_authenticate( pam_handle_t *, int, int, char const ** );
   PAM_EXTERN int pam_sm_setcred( pam_handle_t *, int, int, char const ** );
}

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

   // Get the username
   retval = pam_get_user( pamh, &username, NULL );
   if( (retval != PAM_SUCCESS) || (!username) )
   {
      return PAM_SERVICE_ERR;
   }

   // Converse just to be sure we have a password
   retval = conversation( pamh );
   if( retval != PAM_SUCCESS )
   {
      return PAM_CONV_ERR;
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
