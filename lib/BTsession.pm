#!/usr/bin/perl -w

# A CGI wrapper for session persistent data
# See https://github.com/btesaker/BTsession

use strict;
use Data::Dumper;
use CGI;
use Crypt::CBC;

package BTsession;

(my $scriptbase = $ENV{SCRIPT_NAME}) =~ s|[^/]*$||;

our %DEFAULT = ( magic		=> '%!BTsession',
		 id		=> '',
		 time		=> time(),
		 prefix		=> 'BTsession_',
		 storage	=> '/tmp/.BTsession-',
		 config		=> './.BTsession.config',
		 template	=> './.BTsession.template',
		 cookieName     => '',  # if set use HTTP cookie.
		 cookieExpires  => time() + 24 * 3600,
		 cookiePath     => $scriptbase,
		 cookieDomain   => $ENV{HTTP_HOST},
		 cookieSecure   => 0,
		 usesCookiesIcon => '/UsesCookies.png',
		 usesCookiesURL => '/UsesCookies.html',
		 secret		=> '',	# Crypt-key = secret+sesskey
		 autostore	=> 1,	# Store session when object is deleted
		 namesep	=> ':',	# Separates name components in ID
		 authsep	=> '/',	# Separates auth from name in ID
		 authsize	=> 20,	# digits in keys cookie part
		 debug		=> 0,   # 0:none, 1:STDERR, 2:comment, 3:pre
		 cipher		=> 'Blowfish',
		 );

our $AUTOLOAD;
our $sequence = 0;

# A nonempy @DEBUG turn debuggin on:
#    - @DEBUG is printed to STDOUT enclosed in PRE-tags on oject destruction.
#    - The session file is not encrypted (exposing the secret(s))
#
our @DEBUG = ();
# @DEBUG = ("============= Start debugging ===================\n");
#

sub new {
    my $this = shift;
    my $class = ref($this) || $this;
    my %session = %DEFAULT;
    my $payload = {};
    my $cgi;
    while (@_) {
	my $key = shift;
	if ($key eq 'payload') {
	    $payload = shift;
	}
	elsif ($key eq 'cgi') {
	    my $arg = shift;
	    if    ( !defined($arg) )       { $cgi = new CGI; }
	    elsif ( UNIVERSAL::isa($arg, "UNIVERSAL") 
		    )           	   { $cgi = $arg; }
	    elsif ( ref($arg) eq "ARRAY" ) { $cgi = new CGI(@$arg); }
	    elsif ( ref($arg) eq "HASH" )  { $cgi = new CGI(%$arg); }
	    else                           { $cgi = new CGI($arg); }
	}
	else {
	    $session{$key} = shift;
	}
    }
    $cgi = new CGI unless defined $cgi;
    if (open CONF, '<', $session{config}) {
	while (<CONF>) {
	    chomp;
	    my ($key, $value) = /^\s*(\w+)\s*=(.*)$/;
	    $session{$key} = $value if $key;
	}
	close CONF;
    }

    my $self = { cgi		=> $cgi,	# CGI object
		 session	=> \%session,	# Session data
		 payload       	=> $payload,	# Payload data
	     };
    bless $self, $class;
    if ($self->{session}{id}) {}
    elsif ($self->{session}{cookieName}) {
	$self->{session}{id} = $self->cookie($self->{session}{cookieName});
	$self->{session}{transport} = 'cookie';
    }
    else {
	$self->{session}{id} = $self->session_param('id') || '';
	$self->{session}{transport} = 'param';
    }
    unless ($self->{session}{id}) {
	$self->{session}{id} = $self->session_newid();
	$self->{session}{transport} = '';
	}
    $self->session_load();
    # push @DEBUG, "Load:\n",Data::Dumper::Dumper($self);
    $self->session_init();
    return $self;
}

sub session_param_name {
    my $self = shift;
    return $self->{session}{prefix}.shift();
} 

sub session_param_delete {
    my $self = shift;
    $self->delete($self->session_param_name(shift));
} 

sub session_param {
    my $self = shift;
    my $name = $self->session_param_name(shift);
    my $value = $self->url_param($name);
    $value = $self->param($name) unless defined $value;
    $self->param($name, @_) if @_;
    return $value;
}

sub session_init {} # Hook for implementing auth etc

sub session_store {
    my $self = shift;
    my $id = $self->{session}{id};
    my $cs = $self->{session}{authsep};
    my $magic = $self->{session}{magic}."\n";
    my $secret = $self->{session}{secret};
    (my $name) = split(/$cs.*/, $id);
    my $file = $self->{session}{storage}.$name;
    my $signature = join( ' ',
			  $self->{session}{magic},
			  $self->{session}{secret},
			  $id,
			  );

    # build session structuture into @data with Data::Dumper
    #
    my $dumper = Data::Dumper->new( [ $self->{session},
				      $self->{payload}
				      ],
				    [ 'session',
				      'payload',
				      ],
				    );

    $dumper->Purity(1);
    if ($self->{session}{debug}) {
	$dumper->Indent(1);
   	# $dumper->Sortkeys(1);       # Not implemented in older Data::Dumper.
    }
    else {
	$dumper->Indent(0);	# Minimize storage size.
    }
	
	
    my @data = ( $magic.
		 $self->session_encrypt( "$signature\n", 
					 $dumper->Dump,
					 ),
		 );

    # write session file
    #
    $file =~ /^(.*)$/; $file = $1;
    my $umask = umask(077);
    if (open STORE, '>', "$file.tmp") {
	print STORE @data;
	if (close STORE) {
	    rename "$file.tmp", $file;
	}
	else {
	    warn "Close of '$file' failed: $!\n";
	}
    }
    else {
	warn "Unable to open '$file': $!\n";
    }
    umask($umask);
}

sub session_load {
    my $self = shift;
    my $id = $self->{session}{id};
    my $cs = $self->{session}{authsep};
    my $magic = $self->{session}{magic}."\n";
    my $secret = $self->{session}{secret};
    (my $name) = split(/$cs.*/, $id);
    my $file = $self->{session}{storage}.$name;
    my @stat = stat($file);
    my $signature = join( ' ',
			  $self->{session}{magic},
			  $self->{session}{secret},
			  $id,
			  );

    my @data = ();

    if ( ( @stat and
	   $stat[4] == $> and
	   !($stat[2] & 077) and
	   open(SESSION, '<', $file)
	   ) or
	 ( open(SESSION, '<', $self->{session}{template}) )
	 ) {
	@data = <SESSION>;
	close SESSION;
    }
    @data = () unless (shift(@data) || '') eq $magic;
    my $sig = '';
    my $code = '';
    if (@data) {
	($sig, $code) = split(/\n/, $self->session_decrypt(@data), 2);
    }
    $code = '' unless $sig eq $signature;
    if ($code) {
	my ($session, $payload); 
	$code =~ /^(.*)$/s;
	eval $1;

	if (ref($payload) eq "ARRAY") {
	    @{$self->{payload}} = @$payload;
	}
	elsif (ref($payload) eq "HASH") {
	    foreach (keys %$payload) {
		$self->{payload}{$_} = $$payload{$_};
	    }
	}
	else { 
	    $self->{payload} = $payload;
	}

	$self->{session} = $session;
    }
}

sub session_encrypt {
    my $self = shift;
    my $text = join('', @_);

    return $text if $self->{session}{debug} < 0;

    my $key = $self->{session}{id}.$self->{session}{secret};
    $key =~ /(.*)/;
    $key = $1;
    my $salt = '';
    foreach (1 .. 8) { $salt .= chr(int rand(256)); }
    my $cipher = Crypt::CBC->new( -key		=> $key,
				  -cipher	=> $self->{session}{cipher},
				  -salt	=> $salt,
				  );
    my $code = $cipher->encrypt($text);
    return $code;
}
sub session_decrypt {
    my $self = shift;
    my $code = join('', @_);
    my $key = $self->{session}{id}.$self->{session}{secret};

    return $code if $self->{session}{debug} < 0;

    my $cipher = Crypt::CBC->new( -key	      	=> $key,
				  -cipher	=> $self->{session}{cipher},
				  -salt		=> 1,
				  );
    my $text = $cipher->decrypt($code);
    return $text;
}

sub session_newid {
    my $self = shift;
    use Sys::Hostname;
    return join( $self->{session}{authsep},
		 join( $self->{session}{namesep},
		       time(),
		       hostname(),
		       $$,
		       $sequence++,
		       ),
		 rand(10^$self->{session}{authsize}),
		 );
}
  

sub session_id {
    my $self = shift;
    my $name = $self->{session}{id};
}

sub session_id_field {
    my $self = shift;
    my $name = $self->session_param_name('id');
    return $self->hidden( -name=>$name,
			  -value=>$self->{session}{id},
			  );
}
sub session_user_field {
    my $self = shift;
    return $self->textfield( -name=>$self->session_param_name('user'),
			     -default=>$self->{session}{user},
			     -size=>12,
			     -maxlength=>20,
			     -override=>1,
			     @_,
			     );
}
sub session_pass_field {
    my $self = shift;
    return $self->password_field( -name=>$self->session_param_name('pass'),
				  -value=>'',
				  -size=>12,
				  -maxlength=>20,
				  -override=>1,
				  @_,
				  );
}

sub session_payload {
    my $self = shift;
    my $old = $self->{payload};
    $self->{payload} = shift if @_;
    return $old;
}

sub start_form {
    my $self = shift;
    return $self->{cgi}->start_form(@_) if $self->{session}{cookieName};
    return ( $self->{cgi}->start_form(@_), 
	     $self->session_id_field,
	     );
}

sub uses_cookies {
    my $self = shift;
    my $message = '';
    if ($self->{session}{cookieName}) {
	my $icon = $self->{session}{usesCookiesIcon} || '';
	my $href = $self->{session}{usesCookiesURL} || '';
	my $expires = $self->{session}{cookieExpires} || 0;
	$message = $self->{session}{usesCookiesMessage} || 'Uses cookies';
	if ($icon) {
	    my %img = ( -src=>$icon,
			-border=>0,
			);
	    if ($expires) {
		my @when = localtime($expires);
		$expires = sprintf( "%04d-%02d-%02d %02d:%02d:%02d",
				    $when[5] + 1900,
				    $when[4] + 1,
				    @when[3,2,1,0],
				    );
		$img{-title} = "Session expires $expires";
	    }
	    $message = $self->img(\%img).$message;
	}
	if ($href) {
	    $message = $self->a({-href=>$href}, $message);
	}
    }
    return $message;
}

sub header {
    my $self = shift;
    return $self->{cgi}->header(@_) unless $self->{session}{cookieName};
    my $sess = $self->{session};
    my $options = $_[0];
    $options = {@_} unless ref($options) eq 'HASH';
    my %cookie = ( -name => $$sess{cookieName},
		   -value => $$sess{id},
		   );
    $cookie{-expires} = $$sess{cookieExpires} if  $$sess{cookieExpires};
    $cookie{-path} =    $$sess{cookiePath}    if  $$sess{cookiePath};
    $cookie{-domain} =  $$sess{cookieDomain}  if  $$sess{cookieDomain};
    $cookie{-secure} =  $$sess{cookieSecure}  if  $$sess{cookieSecure};
    my $cookie = $self->cookie(%cookie);
    my $cookielist = [];
    if (exists $$options{'-cookie'}) {
	$cookielist = $$options{'-cookie'};
	$cookielist = [$cookielist] unless ref($cookielist) eq 'ARRAY';
    }
    push(@$cookielist, $cookie);
    $$options{'-cookie'} = $cookielist;
    return $self->{cgi}->header($options);
}

sub redirect {
    my $self = shift;
    return $self->{cgi}->redirect(@_) unless $self->{session}{cookieName};
    my $sess = $self->{session};
    my $options = $_[0];
    $options = {@_} unless ref($options) eq 'HASH';
    my %cookie = ( -name => $$sess{cookieName},
		   -value => $$sess{id},
		   );
    $cookie{-expires} = $$sess{cookieExpires} if  $$sess{cookieExpires};
    $cookie{-path} =    $$sess{cookiePath}    if  $$sess{cookiePath};
    $cookie{-domain} =  $$sess{cookieDomain}  if  $$sess{cookieDomain};
    $cookie{-secure} =  $$sess{cookieSecure}  if  $$sess{cookieSecure};
    my $cookie = $self->cookie(%cookie);
    my $cookielist = [];
    if (exists $$options{'-cookie'}) {
	$cookielist = $$options{'-cookie'};
	$cookielist = [$cookielist] unless ref($cookielist) eq 'ARRAY';
    }
    push(@$cookielist, $cookie);
    $$options{'-cookie'} = $cookielist;
    return $self->{cgi}->redirect($options);
}

sub session_debug {
    my $self = shift;
    my $debug = abs(shift) || 0;
    if ($debug == 1) { print STDERR @DEBUG; }
    if ($debug == 2) { print $self->comment(@DEBUG); }
    if ($debug == 3) { print $self->pre(@DEBUG); }
    return @DEBUG;
}

sub DESTROY {
    my $self = shift;
    if (@DEBUG) {
	# push @DEBUG, "Save:\n", Data::Dumper::Dumper($self);
	$self->session_debug($self->{session}{debug});
    }
    $self->session_store();
}

sub AUTOLOAD {
    my $self = shift;
    (my $method = $AUTOLOAD) =~ s/^.*://;
    my $key = $method;
    if ( $key =~ s/^session_// and exists($self->{session}{$key}) ) {
	my $old = $self->{session}{$key};
	$self->{session}{$key} = shift if @_;
	return $old;
    }
    else {
	$method =~ s/^cgi_//;
	return $self->{cgi}->$method(@_);
    }
}

1;
