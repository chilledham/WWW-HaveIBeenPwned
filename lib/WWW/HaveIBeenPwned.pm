package WWW::HaveIBeenPwned;

use Moo;

use List::Util qw(any);
use URL::Encode ();
use LWP::UserAgent ();
use JSON::MaybeXS ();
use Carp qw(confess);

# WWW::HaveIBeenPwned - Interface to haveibeenpwned API

our $VERSION = '0.02';

has base_url => (
    is       => "rw",
    #isa      => "",
    default  => sub { "https://haveibeenpwned.com/api" },
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

my @auths = qw( url api_version accept );
has auth => (
    is       => "rw",
    isa      => sub {
                        confess sprintf "Invalid auth: '%s'", $_[0]
                        unless any { $_ =~ /\A$_[0]\Z/ } @auths;
                    },
    default  => sub { "url" },
    required => 1,
);

my @services= qw(
    breachedaccount
    breaches
    breach
    dataclasses
    pasteaccount
);

has service => (
    is       => "rw",
    isa     => sub {
                        confess sprintf "Invalid method: '%s'", $_[0]
                        unless any { $_ =~ /\A$_[0]\Z/ } @services;
                   },
    default  => "breachedaccount",
    required => 1,
);

has _uri => (
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

# email  - required
# domain - optional
sub pwned {
    my ($self, $email, $domain) = @_;

    $self->service("breachedaccount");

    my %parameters = (
        truncateResponse => "true",
    );

    $parameters{domain} = lc($domain) if $domain;

    my ($status, $message) = $self->_call_api( $email, \%parameters );

    if ($status eq "200 OK") {
        return JSON::MaybeXS::decode_json( $message );
    }
    elsif ($status eq "404 Not Found") {
        return;
    }
    else {
        confess sprintf "Error processing request: %s %s", $status, $message;
    }
}

## TODO handle empty strings in $domain, and $name in these subs
sub breaches {
    my ($self, $domain) = @_;

    $self->service("breaches");

    my %parameters;
    $parameters{domain} = lc($domain) if $domain;

    my ($status, $message) = $self->_call_api( undef, \%parameters );

    return $status, JSON::MaybeXS::decode_json( $message );
}

sub _call_api_2 {
    my ($self, $service, $parameter, $queries) = @_;

    $self->_setup_auth;

    $self->service( $service );

    $self->_uri( $self->_build_uri( $parameter, $queries ) );
    #print $self->_uri, "\n"; return;

    $self->_lwp->agent( $self->user_agent );

    my $response = $self->_lwp->get( $self->_uri );

# TODO handle JSON::MaybeXS::decode_json erroring when value is empty
    my $resp_message =
        $response->status_line eq "200 OK"
        ? JSON::MaybeXS::decode_json( $response->decoded_content )
        : $response->message;

    return $response->status_line, $resp_message;
}

my @query_params = qw(
    truncateResponse
    domain
);

sub _build_uri {
    my ($self, $parameter, $queries) = @_;

    $parameter = URL::Encode::url_encode($parameter) if $parameter;

    my $query;
    if ( ref $queries && keys %$queries ) {
        $query .= "?" . ( join "&", map { "$_=$queries->{$_}" } grep { $queries->{$_} } @query_params );
    }

    my $uri = join "/", $self->base_url, $self->service, $parameter;
    $uri .= $query if $query;

    return $uri;
}

# TODO should accept be Accept?
my %auth_headers = (
    api_version => 2,
    accept      => "application/vnd.haveibeenpwned.v2+json",
);

sub _setup_auth {
    my ($self) = @_;

    if ($self->auth eq "url") {
        $self->base_url( $self->base_url . "/v2" )
            unless $self->base_url =~ /v2/;
    }

    if ( any { $_ =~ /$self->auth/ } keys %auth_headers ) {
        $self->_lwp->default_header( $self->auth => $auth_headers{ $self->auth } );
    }

    return;
}

sub breach {
    my ($self, $name) = @_;

    $self->service("breach");

    my ($status, $message) = $self->_call_api( $name );

    return $status, JSON::MaybeXS::decode_json( $message );
}

sub dataclasses {
    my ($self) = @_;

    $self->service("dataclasses");

    my ($status, $dataclasses) = $self->_call_api();

    return $status, JSON::MaybeXS::decode_json( $dataclasses );
}

sub pasteaccount {
    my ($self, $email) = @_;

    $self->service("pasteaccount");

    my ($status, $message) = $self->_call_api( $email );

    return $status, JSON::MaybeXS::decode_json( $message );
}

sub _call_api {
    my ($self, $method, $parameters) = @_;
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

    my $uri = $self->base_url;

    # handle version specifier in URL
    $uri .= "v2/" if $self->auth eq "url";
    $uri .= $self->service . "/";

    $uri .= URL::Encode::url_encode($method) if $method;

    if (ref $parameters && keys %$parameters) {
        $uri .= "?" . ( join "&", map { "$_=$parameters->{$_}" } keys %$parameters );
    }

    # handle version specifier in headers (api-version or Accept)
    unless ( $self->auth eq "url" ) {
        $self->_lwp->default_header(
            $self->auth eq "api_version"
                ? ($self->auth => 2)
                : ($self->auth => "application/vnd.haveibeenpwned.v2+json")
        );
    }

    $self->_lwp->agent( $self->user_agent );

    my $response = $self->_lwp->get( $uri );

    my $resp_message =
        $response->status_line eq "200 OK"
        ? $response->decoded_content
        : $response->message;

    return $response->status_line, $resp_message;
}

=head1 AUTHOR

collin seaton, C<< <cseaton at cpan.org> >>

=head1 LICENSE AND COPYRIGHT

Copyright 2017 collin seaton.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See L<http://dev.perl.org/licenses/> for more information.


=cut

1;
