package Knock;

use Mojo::Base 'Mojo::MITM::Plugin';

### run like this:
# mojo-mitm -l http://199.88.77.44:80 -p plugins/Knock.pm,code=mysecret
#
# to unlock access visit: http://199.88.77.44:80/mysecret

has code => 'knock.knock.knock';
has allowed => sub { {} };

sub on_request {
  my ($self, $id, $tx, $stash) = @_;

  return if $self->allowed->{$tx->remote_address};
  die "FATAL: you need to knock first" unless $tx->req->url->path eq '/' . $self->code;
  
  $self->allowed->{$tx->remote_address} = 1;
  $tx->res->code(200)->message('OK')->body('Welcome '.$tx->remote_address);
}

1;