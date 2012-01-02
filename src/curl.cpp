#include "curl.hpp"

#include <cstring>
#include <cstdlib>

#include <iostream>
#include <sstream>
#include <stdexcept>

//
// Static helper functions
//

//
// Public methods
//

Curl::Curl()
   : curl( curl_easy_init() ),
     host( "http://localhost:5984" )
{
}

Curl::~Curl()
{
   curl_easy_cleanup( curl );
   curl = NULL;
}


bool Curl::checkAuthorized( char const * username,
                            char const * password )
{
   char * usernameUE = curl_easy_escape( curl, username, 0 );
   char * passwordUE = curl_easy_escape( curl, password, 0 );

   std::stringstream postS;
   postS << "name=" << usernameUE
         << "&password=" << passwordUE;
   std::string postStr = postS.str();
   curl_free( usernameUE );
   curl_free( passwordUE );

   // Set up the URL.
   char * url = strdup( (host + "/_session").c_str() );
   char * post = strndup( postStr.c_str(), postStr.length() );

   // Set the URL to which we post
   curl_easy_setopt( curl, CURLOPT_URL, url );

   // Set the data to be posted
   curl_easy_setopt( curl, CURLOPT_POSTFIELDS, post );

   // Perform the check
   CURLcode res = curl_easy_perform( curl );
   if( res != 0 )
   {
      free( post );
      free( url );
      throw std::runtime_error( "Could not perform lookup" );
   }

   // Tear down the data we allocated
   free( post );
   free( url );

   long status = 500;
   res = curl_easy_getinfo( curl, CURLINFO_RESPONSE_CODE, & status );
   if( res != 0 )
   {
      free( post );
      free( url );
      throw std::runtime_error( "Could not perform lookup" );
   }

   return status == 200;
}

//
// Private methods
//
