package Apache::AuthNetLDAP;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;

use Apache::Constants qw(:common);
use Net::LDAP;

@ISA = qw(Exporter AutoLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
	
);
$VERSION = '0.19';


# Preloaded methods go here.

#handles Apache requests
sub handler
{
   my $r = shift; 

   my ($result, $password) = $r->get_basic_auth_pw;
   return $result if $result; 
  
   my $username = $r->connection->user;

   my $binddn = $r->dir_config('BindDN') || "";
   my $bindpwd = $r->dir_config('BindPWD') || "";
   my $basedn = $r->dir_config('BaseDN') || "";
   my $ldapserver = $r->dir_config('LDAPServer') || "localhost";
   my $ldapport = $r->dir_config('LDAPPort') || 389;
   my $uidattr = $r->dir_config('UIDAttr') || "uid";
 
    if ($password eq "") {
        $r->note_basic_auth_failure;
        $r->log_reason("user $username: no password supplied",$r->uri);
        return AUTH_REQUIRED;
    }
 
  
   my $ldap = new Net::LDAP($ldapserver, port => $ldapport);

   my $mesg;
   #initial bind as user in Apache config
   if ($bindpwd ne "")
   {
       $mesg = $ldap->bind($binddn, password=>$bindpwd);
   }
   else
   {
       $mesg = $ldap->bind();
   }
  
   #each error message has an LDAP error code
   if (my $error = $mesg->code())
   {
        $r->note_basic_auth_failure;
        $r->log_reason("user $username: LDAP Connection Failed: $error",$r->uri);
        return AUTH_REQUIRED; 
   }
  
  
  #Look for user based on UIDAttr
  
   my $attrs = ['dn'];
  $mesg = $ldap->search(
                  base => $basedn,
                  scope => 'sub',                  
                  filter => "($uidattr=$username)",
                  attrs => $attrs
                 );

    if (my $error = $mesg->code())
   {
        $r->note_basic_auth_failure;
        $r->log_reason("user $username: LDAP Connection Failed: $error",$r->uri);
        return AUTH_REQUIRED;
   }

   unless ($mesg->count())
   {
        $r->note_basic_auth_failure;
        $r->log_reason("user $username: user entry not found for filter: $uidattr=$username",$r->uri);
        return AUTH_REQUIRED;
   }
 
   #now try to authenticate as user
   my $entry = $mesg->shift_entry;
   $mesg = $ldap->bind($entry->dn(),password=>$password);

 
  if (my $error = $mesg->code())
  {
        $r->note_basic_auth_failure;
        $r->log_reason("user $username: failed bind: $error",$r->uri);
        return AUTH_REQUIRED;
   }
        my $error = $mesg->code();
        my $dn = $entry->dn();
        #$r->log_reason("AUTHDEBUG user $dn:$password bind: $error",$r->uri);

 return OK;
}
# Autoload methods go after =cut, and are processed by the autosplit program.

# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Apache::AuthNetLDAP - mod_perl module that uses the Net::LDAP module for user authentication for Apache 

=head1 SYNOPSIS

 AuthName "LDAP Test Auth"
 AuthType Basic

 #only set the next two if you need to bind as a user for searching
 #PerlSetVar BindDN "uid=user1,ou=people,o=acme.com" #optional
 #PerlSetVar BindPWD "password" #optional
 PerlSetVar BaseDN "ou=people,o=acme.com"
 PerlSetVar LDAPServer ldap.acme.com
 PerlSetVar LDAPPort 389
 #PerlSetVar UIDAttr uid
 PerlSetVar UIDAttr mail

 require valid-user

 PerlAuthenHandler Apache::AuthNetLDAP

=head1 DESCRIPTION

This module authenticates users via LDAP using the Net::LDAP module. This module is Graham Barr's "pure" Perl LDAP API. 

It also uses all of the same parameters as the Apache::AuthPerLDAP, but I have added two extra parameters. 

The parameters are:

=over 4

=item PerlSetVar BindDN

Used to set initial LDAP user.

=item PerlSetVar BindPWD

Used to set initial LDAP password.

=item PerlSetVar BaseDN

This sets the search base used when looking up a user in an LDAP server.

=item PerlSetVar LDAPServer 

This is the hostname of the LDAP server you wish to use.

=item PerlSetVar LDAPPort 

This is the port the LDAP server is listening on.

=item PerlSetVar UIDAttr

The attribute used to lookup the user.

=back

=head2 Uses for UIDAttr

For example if you set the UIDAttr to uid, then the LDAP search filter will lookup a user using the search filter:

Normally you will use the uid attribute, but you may want (need) to use a different attribute depending on your LDAP server or to synchronize with different applications. For example some versions of Novell's LDAP servers that I've encountered stored the user's login name in the cn attribute (a really bad idea). And the Netscape Address Book uses a user's email address as the login id.

=head1 INSTALLATION 

It's a pretty straightforward install if you already have mod_perl and Net::LDAP already installed.

After you have unpacked the distribution type:

perl Makefile.PL
make 
make install

Then in your httpd.conf file or .htaccess file, in either a <Directory> or <Location> section put:

 AuthName "LDAP Test Auth"
 AuthType Basic

 #only set the next two if you need to bind as a user for searching
 #PerlSetVar BindDN "uid=user1,ou=people,o=acme.com" #optional
 #PerlSetVar BindPWD "password" #optional
 PerlSetVar BaseDN "ou=people,o=acme.com"
 PerlSetVar LDAPServer ldap.acme.com
 PerlSetVar LDAPPort 389
 PerlSetVar UIDAttr uid 

 require valid-user

 PerlAuthenHandler Apache::AuthNetLDAP

=head1 HOMEPAGE

	Module Home:http://courses.unt.edu/mewilcox/

=head1 AUTHOR
   	Mark Wilcox mewilcox@unt.edu

=head1 SEE ALSO
   L<Net::LDAP>
  

=head1 ACKNOWLEDGMENTS

 Graham Barr for writing Net::LDAP module.
 Henrik Strom for writing the Apache::AuthPerLDAP module which I derived this from.
 The O'Reilly "Programming Modules for Apache with Perl and C" (http://www.modperl.com).

=head1 WARRANTY AND LICENSE
You can distribute and modify in accordance to the same license as Perl. Though I would like to know how you are using the module or if you are using the module at all.

Like most of the stuff on the 'net, I got this copy to work for me without destroying mankind, you're mileage may vary.

=cut


1;
__END__
