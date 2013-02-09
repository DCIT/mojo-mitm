use strict;
use warnings;

use Test::More tests => 1;

my $ok;
END { BAIL_OUT "Could not load all modules" unless $ok }

use Mojo::MITM::Proxy;

my @plugin_files = (<plugins/*.pm>);
my $p = Mojo::MITM::Proxy->new(fake_ca=>0, plugins_to_load=>\@plugin_files);

ok 1, 'All plugins loaded successfully';
$ok = 1;
 