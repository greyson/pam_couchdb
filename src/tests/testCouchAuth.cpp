#include <curl.hpp>

#include <iostream>
#include <stdexcept>

int main( int argc, char ** argv )
{
   if( argc != 3 )
   {
      throw std::runtime_error( "Need a username and password" );
   }

   Curl curl;
   if( curl.checkAuthorized( argv[1], argv[2] ) )
   {
      std::cerr << "USER IS AUTHORIZED" << std::endl;
   }
   else
   {
      std::cerr << "USER IS UNAUTHORIZED" << std::endl;
   }
   return 0;
}
