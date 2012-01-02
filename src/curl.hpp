#ifndef __CPAM_CURL_HPP__
#define __CPAM_CURL_HPP__

#include <curl/curl.h>

#include <string>

class Curl
{
public:
   Curl();
   virtual ~Curl();

   bool checkAuthorized( char const * username,
                         char const * password );

   //
   // Accessible from the helper functions
   //

   size_t readPost( void * data, size_t size, size_t nMember );

private:
   CURL * curl;
   std::string host;
};

#endif // __CPAM_CURL_HPP__
