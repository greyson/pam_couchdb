#include "curl.hpp"

#include <cstring>
#include <cstdlib>

#include <iostream>
#include <sstream>
#include <stdexcept>

//
// Static helper functions
//

static size_t static_onHeader( void * d, size_t sz, size_t nm, void * self )
{
   Curl * curl = (Curl*)self;
   return curl->onHeader( d, sz, nm );
}

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

   // Set the reading function for the headers
   curl_easy_setopt( curl, CURLOPT_HEADERFUNCTION, & static_onHeader );
   curl_easy_setopt( curl, CURLOPT_HEADERDATA, this );

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

   return status == 200;
}

//
// Private methods
//

size_t Curl::onHeader( void * data, size_t size, size_t nMember )
{
   static std::string const httpheader = "HTTP/1.1";

   // Get the status
   std::string headerString( (char const *) data, size * nMember );
   std::stringstream header( headerString );

   std::string tok;
   header >> tok;

   if( tok == httpheader )
   {
      header >> status;
   }
   else
   {
      std::cout << "HEADER: " << headerString << std::endl;
   }

   return size * nMember;
}
