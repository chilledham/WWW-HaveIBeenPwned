#! perl

use 5.006;
use strict;
use warnings;

use Test::More;

BEGIN {
    use FindBin;
    use lib "$FindBin::Bin/../lib";
}

#plan tests => 1;

use_ok("WWW::HaveIBeenPwned");

diag( "Testing WWW::HaveIBeenPwned $WWW::HaveIBeenPwned::VERSION, Perl $], $^X" );

my $pwned = WWW::HaveIBeenPwned->new();
isa_ok($pwned, "WWW::HaveIBeenPwned");

my $sites = $pwned->pwned('test@example.com');



done_testing();
