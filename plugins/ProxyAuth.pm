package ProxyAuth;

use Mojo::Base 'Mojo::MITM::Plugin';

### usage:
# mojo-mitm -p plugins/ProxyAuth.pm,userinfo=user:passwd

has userinfo => 'proxy:proxy';

sub on_connect {
  my ($self, $id, $tx, $stash) = @_;

  if (!$tx->req->proxy || $tx->req->proxy->userinfo ne $self->userinfo) {
    $tx->res->code(407);
    $tx->res->message('Proxy Authentication Required');
    $tx->res->headers->header('Proxy-Authenticate' => 'Basic');
  }
}

sub on_request {
  my ($self, $id, $tx, $stash) = @_;

  return if $stash->{tls} && $stash->{tls} eq 'connect';

  if (!$tx->req->proxy || $tx->req->proxy->userinfo ne $self->userinfo) {
    $tx->res->code(407);
    $tx->res->message('Proxy Authentication Required');
    $tx->res->headers->header('Proxy-Authenticate' => 'Basic');
  }
}

sub on_response {
  #my ($self, $id, $tx, $stash) = @_;
}

1;