# $Id: AuthenDBMCache.pm,v 1.6 2002/10/23 16:03:36 reggers Exp $
#
# Author          : Reg Quinton
# Created On      : 23-Sep-2002 
# Derivation      : from AuthenCache by Jason Bodnar, Christian Gilmore
# Status          : Functional
#
# PURPOSE
#    User Authentication Cache implemented in a DBM database.

# Package name

package Apache::AuthenDBMCache;

# Required libraries

use strict;
use mod_perl ();
use Apache::Constants qw(OK AUTH_REQUIRED DECLINED DONE);
use Apache::Log ();
use Carp;

# Global variables

$Apache::AuthenDBMCache::VERSION = '0.01';

# local subroutines and data not exported to anyone

my($cache)= "/var/adm/authen-web/cache";

# key index to value -- an expiration date.

sub GetCache {
    my (%DBM);    my($key)=@_;

    croak "No access to $cache"
	unless dbmopen(%DBM,$cache,0600);

    my ($tmp)=$DBM{$key}; dbmclose(%DBM);

    return ($tmp);
}

sub SetCache {
    my (%DBM);    my ($key,$val)=@_;

    croak "No access to $cache"
	unless dbmopen(%DBM,$cache,0600);

    $DBM{$key}=$val;    dbmclose(%DBM);
}

sub ExpireCache {
    my (%DBM,$key,$now);

    croak "No access to $cache"
	unless dbmopen(%DBM,$cache,0600);

    $now=time();

    foreach $key (keys %DBM) {
	delete $DBM{$key} if $DBM{$key} < $now;
    }

    dbmclose(%DBM);

}

# squish userid, password, config and realm into a hash

sub Digest {
    use MD5;

    my ($string)=MD5->hexhash(@_);
    $string=~ s/[^0-9a-zA-Z]//g;
    return($string);
}

# handler: hook into Apache/mod_perl API

sub handler {
  my $r = shift;
  return OK unless $r->is_initial_req; # only the first internal request

  # Get configuration... are we debugging?

  my $debug = (lc($r->dir_config('AuthenDBMCache_Debug')) eq 'on');

  # Get response and password

  my($res, $passwd) = $r->get_basic_auth_pw;
  return $res if $res; # e.g. HTTP_UNAUTHORIZED

  # Get username and Realm

  my $realm = lc($r->auth_name);
  my $user  = lc($r->connection->user);
  return DECLINED  unless ($user);

  # Get all parameters -- current config

  my $config=$r->dir_config();  $config=join(":",%$config);

  # construct a unique key for userid/realm/config/password

  my $key   = Digest("$user $realm $config $passwd");

  $r->log->debug("handler: user=$user") if $debug;

  # if there is an expiration date for that key

  if (my $exp = GetCache("$key")) {
      return DECLINED unless ($exp > time());

      # Hash hasn't expired, password is ok, clear the stacked handlers

      $r->log->debug("handler: $user cache hit") if $debug;
      $r->set_handlers(PerlAuthenHandler => undef);
      return OK;
  }

  # that key is not in cache

  $r->log->debug("handler: user cache miss") if $debug;
  return DECLINED;
}

# manage_cache: insert new entries into the cache

sub manage_cache {
  my $r = shift;
  return OK unless $r->is_initial_req; # only the first internal request

  # Get configuration

  my $ttl   = $r->dir_config('AuthenDBMCache_TTL') || 3600;
  my $debug = (lc($r->dir_config('AuthenDBMCache_Debug')) eq 'on');

  # Get response and password

  my ($res, $passwd) = $r->get_basic_auth_pw;
  return $res if $res; # e.g. HTTP_UNAUTHORIZED

  # Get username and Realm

  my $realm = lc($r->auth_name);
  my $user  = lc($r->connection->user);
  return DECLINED  unless ($user);

  # Get all parameters -- current config

  my $config=$r->dir_config();  $config=join(":",%$config);

  # construct a unique key for userid/realm/config/password

  my $key   = Digest("$user $realm $config $passwd");

  $r->log->debug("manage_cache: user=$user") if $debug;

  # Add the key to the cache with an expiration date

  SetCache("$key",time() + $ttl);

  $r->log->debug("manage_cache: $user cache add") if $debug;

  return OK;
}

1;

__END__

# Documentation - try 'pod2text AuthenCache.pm'

=head1 NAME

Apache::AuthenDBMCache - Authentication caching

=head1 SYNOPSIS

 # In your httpd.conf

 PerlModule Apache::AuthenDBMCache

 # In httpd.conf or .htaccess:

 AuthName Name
 AuthType Basic

 PerlAuthenHandler Apache::AuthenDBMCache <Primary Authentication Module> Apache::AuthenDBMCache::manage_cache

 # Typical constraints one of these

 require valid-user
 require user larry moe curly

 # Optional parameters/Defaults are listed to the right.

 PerlSetVar AuthenDBMCache_TTL           900 # Default: 3600 sec
 PerlSetVar AuthenDBMCache_Debug         On  # Default: Off

=head1 DESCRIPTION

B<Apache::AuthenDBMCache> implements a caching mechanism in order to
speed up authentication and to reduce the usage of system
resources. It must be used in conjunction with a regular mod_perl
authentication module (we use it to accelerate AuthenURL and AuthenSMB
methods but it can be used with any perl authentication module).

When a authorization request is received this handler uses a DBM data
base cache to answer the request. Each entry in the cache is indexed
by a key which is a hash of user name, the authentication "realm", the
authentication parameters and the password. The value at the key is an
expiration date. If the supplied user name and password hash to a key
which exists and has not expired then the handler returns OK and
clears the downstream Authen handlers from the stack. Otherwise, it
returns DECLINED and allows the next PerlAuthenHandler in the stack to
be called.

After the primary authentication handler completes with an OK,
AuthenDBMCache::manage_cache adds the new hash to the cache with an
appropriate expiration date.

=head1 CONFIGURATION OPTIONS

The following variables can be defined within the configuration
of Directory, Location, or Files blocks or within .htaccess
files.

=head2 PerlSetVar AuthenDBMCache_TTL 3600

The B<AuthenDBMCache_TTL> variable contains the "Time to Live" in
seconds of entries within the cache.  The default value is one hour
(3600 seconds). When entries are created in the cache they're marked
with an expiration date calculated from the TTL value.

=head2 PerlSetVar AuthenDBMCache_Debug off

If the B<AuthenDBMCache_Debug> variable is set to "on" some debugging
messages are logged.

=head1 FUNCTIONS

The function B<Apache::AuthenDBMCache::ExpireCache> will expire all cache entries that are no longer current.

=head1 BUGS/BEWARE

The cache files (cache.dir and cache.pag in the /var/adm/authen-web directory)
should exist and belong to the userid of the web server. They should be
protected so that nobody else can read them. The module will croak if it
cannot access the data.

We make no effort to lock the database. The worst case that can happen
is we return a false negative and that has no serious consequences.

Other processes are required to purge the cache of entries which have
expired -- use the B<Apache::AuthenDBMCache::ExpireCache> function. A
periodic job that invokes perl like this will suffice

	perl -MApache::AuthenDBMCache -e Apache::AuthenDBMCache::ExpireCache

=head1 SEE ALSO

httpd(8), mod_perl(1), MD5

=head1 AUTHORS

Reg Quinton E<lt>reggers@uwaterloo.caE<gt> from AuthenCache by Jason Bodnar
and Christian Gilmore.

=head1 COPYRIGHT

Copyright (C) 2002, Reg Quinton. AuthenCache Copyright (C) 1998-2001,
Jason Bodnar.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.
