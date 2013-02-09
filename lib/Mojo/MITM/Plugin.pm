package Mojo::MITM::Plugin;

use Mojo::Base -base;

has proxy => undef;

sub on_connect {}
sub on_init {}
sub on_exit {}
sub on_request {}
sub on_response {}

1;
