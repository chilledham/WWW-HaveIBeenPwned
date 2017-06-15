package WWW::HaveIBeenPwned;

use Moo;

use List::Util qw(any);
use URI::Escape ();
use LWP::UserAgent ();
use JSON::MaybeXS ();
use Carp qw(confess);

$WWW::HaveIBeenPwned::VERSION = '0.02';

has base_url => (
    is       => "rw",
    #isa      => "",
    default  => sub { "https://haveibeenpwned.com/api" },
    required => 1,
);

# service can be:
#   breachedaccount
#     - parameters:
#       truncateResponse=true
#       domain=example.com
#   breaches
#     - parameters:
#       domain=example.com
#   breach
#   dataclasses
#   pasteaccount
#

my @services = qw(
    breachedaccount
    breaches
    breach
    dataclasses
    pasteaccount
);

has service => (
    is       => "rw",
    isa     => sub {
                        confess sprintf "Invalid service: '%s'", $_[0]
                        unless any { $_ =~ /\A$_[0]\Z/ } @services;
                   },
    default  => "breachedaccount",
    required => 1,
);

my @auths = qw( url api_version accept Accept );
has auth => (
    is       => "rw",
    isa      => sub {
                        confess sprintf "Invalid auth: '%s'", $_[0]
                        unless any { $_ =~ /\A$_[0]\Z/ } @auths;
                    },
    default  => sub { "url" },
    required => 1,
);

has user_agent => (
    is       => "rw",
    isa      => sub {
                        confess sprintf "Invalid user_agent: '%s'", $_[0]
                        if ref $_[0] || $_[0] !~ m{\A[ -~]+\Z}i;
                    },
    default  => sub { "Pwnage-Checker-For-Perl" },
    required => 1,
);

has uri => (
    is      => "rw",
    #isa     => "",
);

has _lwp => (
    is      => "ro",
    isa     => sub {
                        confess "Only LWP::UserAgent supported"
                        unless ref $_[0] eq "LWP::UserAgent";
                   },
    default => sub { LWP::UserAgent->new(); },
);

has _query_params => (
    is      => "ro",
    default => sub { [qw(truncateResponse domain)] },
);

sub breachedaccount {
    my ($self, $account, $params) = @_;

    confess "'\$account' is required" unless $account;

    my %queries = $self->_build_query_params( $params );

    return $self->_call_api( "breachedaccount", $account, \%queries );
}

# email  - required
# domain - optional
sub pwned {
    my ($self, $account, $params) = @_;

    $params->{truncateResponse} = "true";

    my ($status, $message) = $self->breachedaccount( $account, $params );

    if ($status eq "200 OK") {
        return $message;
    }
    elsif ($status eq "404 Not Found") {
        return;
    }
    else {
        confess sprintf "Error processing request: %s %s", $status, $message;
    }
}

sub breaches {
    my ($self, $params) = @_;

    my %queries = $self->_build_query_params( $params );

    return $self->_call_api("breaches", undef, \%queries);
}

sub breach {
    my ($self, $name) = @_;

    confess "'\$name' is required" unless $name;

    return $self->_call_api("breach", $name);
}

sub dataclasses {
    return $_[0]->_call_api("dataclasses");
}

sub pasteaccount {
    my ($self, $account) = @_;

    confess "'\$account' is required" unless $account;

    return $self->_call_api("pasteaccount", $account);
}

sub _call_api {
    my ($self, $service, $parameter, $queries) = @_;

    $self->_auth;

    $self->service( $service );

    $self->uri( $self->_build_uri( $parameter, $queries ) );
#    print $self->uri, "\n"; return;

    $self->_lwp->agent( $self->user_agent );

    my $response = $self->_lwp->get( $self->uri );

    my $resp_message =
        $response->status_line eq "200 OK"
        ? JSON::MaybeXS::decode_json( $response->decoded_content )
        : $response->message;

    return $response->status_line, $resp_message;
}

my %auth_headers = (
    api_version => 2,
    accept      => "application/vnd.haveibeenpwned.v2+json",
    Accept      => "application/vnd.haveibeenpwned.v2+json",
);

sub _auth {
    my ($self) = @_;

    $self->auth("url") unless $self->auth;

    if ($self->auth eq "url" and not $self->base_url =~ /v2/ ) {
        $self->base_url( $self->base_url . "/v2" );
    }

    if ( exists $auth_headers{ $self->auth } ) {
        $self->auth("Accept") if $self->auth eq "accept";
        $self->_lwp->default_header( $self->auth => $auth_headers{ $self->auth } );
    }

    return;
}

sub _build_uri {
    my ($self, $parameter, $queries) = @_;

    $parameter = URI::Escape::uri_escape($parameter) if $parameter;

    my $query;
    if ( ref $queries && keys %$queries ) {
        $query .= "?" . ( join "&", map { "$_=$queries->{$_}" } grep { $queries->{$_} } @{ $self->_query_params } );
    }

    my $uri = join "/", $self->base_url, $self->service;
    $uri .= "/$parameter" if $parameter;
    $uri .= $query if $query;

    return $uri;
}

sub _build_query_params {
    my ($self, $params) = @_;

    my %query_params =
        map { $_ => $params->{$_} }
        grep { $params->{$_} }
        @{ $self->_query_params };

    return %query_params;
}

=head1 NAME

WWW::HaveIBeenPwned - Interface to haveibeenpwned API

=head1 VERSION

 0.02

=head1 SYNOPSIS

 use WWW::HaveIBeenPwned;
 $pwned = WWW::HaveIBeenPwned->new();
 if ( my $sites = $pwned->pwned( $account ) ) {
     print "$account has been pwned\n";
     print "\t$_->{Name}\n" for @$sites;
 }

=head1 INSTALLATION

Something about LWP::Protocol::https and how irritating it is to install

=head1 METHODS

=over 4

=item new

=item pwned

=item breacheaccount

=item breaches

=item breach

=item dataclass

=item pasteaccount

=back

=head1 ATTRIBUTION

Troy Hunt

';--have i been pwned?

L<https://haveibeenpwned.com>

';--have i been pwned? is the source of all data; this is simply a Perl
interface to that data.

';--have i been pwned? is licensed under Creative Commons Attribution 4.0
International Licence.

CC BY 4.0 L<https://creativecommons.org/licenses/by/4.0/>

=head1 LICENSE AND COPYRIGHT

This software is licenced under Creative Commons Attribution 4.0
CC BY 4.0 L<https://creativecommons.org/licenses/by/4.0/>

Copyright 2017 collin seaton.

=head1 AUTHOR

collin seaton, C<< <cseaton at cpan.org> >>

=cut

1;
