#! perl

use 5.006;
use strict;
use warnings;

use Test::More tests => 33;;

BEGIN {
    use FindBin;
    use lib "$FindBin::Bin/../lib";
}

#plan tests => 1;

use_ok("WWW::HaveIBeenPwned");

diag( "Testing WWW::HaveIBeenPwned $WWW::HaveIBeenPwned::VERSION, Perl $], $^X" );

my $pwned = WWW::HaveIBeenPwned->new();
isa_ok($pwned, "WWW::HaveIBeenPwned");

# check attributes have sane defaults set
ok( $pwned->base_url eq "https://haveibeenpwned.com/api", "'base_url' set: " . $pwned->base_url );
ok( $pwned->service eq "breachedaccount", "'service' set: " . $pwned->service );
ok( $pwned->auth eq "url", "'auth' set: " . $pwned->auth );
ok( $pwned->user_agent eq "Pwnage-Checker-For-Perl", "'user_agent' set: " . $pwned->user_agent );

# internal attributes
isa_ok( $pwned->_lwp, "LWP::UserAgent", "LWP::UserAgent" );
is_deeply( $pwned->_query_params, [qw(truncateResponse domain)], "Query parameters validated" );

# services supported
my @services = qw(
    breachedaccount
    breaches
    breach
    dataclasses
    pasteaccount
);

for my $service (@services) {
    $pwned->service($service);

    ok( $pwned->service eq $service, "Available service: $service" );
}

# services not supported. partial list.
my @not_services = qw(
    breachedwhale
    brushes
    shakabrah
    doctorspaceman
    plastic
);

for my $nicht_service (@not_services) {
    eval { $pwned->service($nicht_service); };
    isnt( $@, defined, "Nonsense service not supported: $nicht_service" );
}

# auths supported
my @auths = qw( url api_version accept Accept );

for my $auth (@auths) {
    $pwned->auth($auth);

    ok( $pwned->auth eq $auth, "Available auth: $auth" );
}

# auths not supported. not exhaustive list.
my @not_auths = qw(
    kneeprint
    haircount
    radiocarbondating
    ringcounting
    eyescent
);

for my $nein_auth (@not_auths) {
    eval { $pwned->service($nein_auth); };
    isnt( $@, defined, "Awkward auth not supported: $nein_auth" );
}

# URI testing
$pwned = WWW::HaveIBeenPwned->new();

# no auth, no query parameter
is( $pwned->_build_uri('test@example.com'),
    "https://haveibeenpwned.com/api/breachedaccount/test%40example.com",
    "URL built. No auth, no query parameter"
);

# no auth, yes query parameter
is( $pwned->_build_uri('test@example.com', {domain => "dropbox.com"}),
    "https://haveibeenpwned.com/api/breachedaccount/test%40example.com?domain=dropbox.com",
    "URL built. No auth, yes query parameter"
);

$pwned->_auth;

# yes auth, no query parameter
is( $pwned->_build_uri('test@example.com'),
    "https://haveibeenpwned.com/api/v2/breachedaccount/test%40example.com",
    "URL built. Yes auth, no query parameter"
);

# yes auth, yes query parameter
is( $pwned->_build_uri('test@example.com', {domain => "dropbox.com"}),
    "https://haveibeenpwned.com/api/v2/breachedaccount/test%40example.com?domain=dropbox.com",
    "URL built. Yes auth, yes query parameter"
);

# how are query parameters doing?
my %queries = (
    truncateResponse => "true",
    domain           => "dropbox.com",
);
my %params = $pwned->_build_query_params( \%queries );
is_deeply( \%queries, \%params, "Query parameter manipulation sane" );

my %niet_queries = (
    elementNotSeenInThisFilm => "truth",
    %queries,
);
%params = $pwned->_build_query_params( \%niet_queries );
is_deeply( \%queries, \%params, "Query parameter manipulation still sane" );

#done_testing();

