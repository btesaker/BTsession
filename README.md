# BTsession
CGI wrapper for session data

BTsession stores a datastructure on file between activations

## Synopsis
use BTsession;
my %data = ();
my $session = BTsession->new( -payload=>\%data );


## BTsession overview:

Primary objective for this module is to keep state information between 
CGI transactions. A session is identified by a session id passed as a
hidden CGI parameter.

The state is stored in encrypted form. In addition to session parameters 
it may store a user defined payload. 

The new() method creates a session object and, if a valid session id is 
present, load the previous saved state. The state is by default saved on
destruction of the session object.

The session behavior may be controlled by session parameters. These may be 
set by the session_parameter() method, passed to the new() method, read 
from a config file or default to compile in values. Parameters is passed 
to new() in key,value pairs, typicaly using the => notation.

There are two special parameters that may not be read from the config file:

### cgi: 
By default a new CGI object is created inside the BTsession object.
Parameters to the CGI->new() method may be specified in the new() method. 
If the cgi parameter is a referense to a CGI object, this is uses instead
of creating a new. All unknown methods are passed to the CGI object. 
The CGI object may be retrieved or replaced with the session_cgi() method.

### payload:
This is the user data to store in the session object. Its typicaly a 
reference to a hash or an object. The complete structure referenced is 
stored and loaded with the Data::Dumper module. The payload is typically 
passed til the new(), but may be retrieved or replaced with the 
session_payload() method.


## Passing the session key:

By default the session ID is passed as a CGI parameter. The start_form() is 
overloaded to add a hidden field. 

If the setting variable "cookieName" is true, it uses HTTP cookies instead, 
using the session id as the value. The header() is overloaded to include the 
cookie in the header.

new() is responsible for retrieving the session ID.


## Encryption

Encryption of the storage is done by the CBC module with Blowfish as default 
cipher. The encryption key is a combination of the session key and the 
"secret" session parameter.

To avoid fake sessions the store file is checked for ownership 
and permission before beeing trusted, but the secret should also be protected.
This is typiclly done by setuid and file protection of the config file. 

Negative debug levels turn off encryption of the storage field. Use with
cation since this reduses the security. 


## Sample application:
===================

    #!/usr/bin/perl -w
    #
    # Load module, declare payload with defaults and create session object
    #
    use BTsession;
    my %data = ( time => time() );
    my $session = new BTsession( payload => \%data );
    #
    # If reset is checked, the time payload field is updated. Clear reset.
    #
    $data{time} = time() if $session->param("reset");
    $session->param("reset", "");
    #
    # Print the form.
    #
    print(  $session->header(),
    	    $session->start_html("BTsession test"),
       	    time() - $data{time} , " seconds since last reset",
            $session->start_form(),
            $session->checkbox(
		-name =>    "reset",
         	-value =>   "ON",
                -label =>   "Reset time",
                ), $session->br(),
            $session->submit(),
            $session->end_form(),
            $session->end_html(),
            );
