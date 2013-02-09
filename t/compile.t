use strict;
use warnings;

use Test::More tests => 1;

diag( "Testing Mojo::MITM $Mojo::MITM::VERSION, Perl $], $^X" );

my $ok;
END { BAIL_OUT "Could not load all modules" unless $ok }

use Mojo::MITM;
use Mojo::MITM::Proxy;
use Mojo::MITM::CA;
use Mojo::MITM::Logger;
use Mojo::MITM::Plugin;

ok 1, 'All modules loaded successfully';
$ok = 1;
 