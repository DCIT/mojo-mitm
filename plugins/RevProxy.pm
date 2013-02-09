package RevProxy;

use Mojo::Base 'Mojo::MITM::Plugin';

### usage:
# mojo-mitm -p plugins/RevProxy.pm,target=https://twitter.com

has target  => 'http://example.com';
has _remote => sub { Mojo::URL->new(shift->target) };
has _local  => sub { Mojo::URL->new(shift->proxy->listen->[0]) };

sub on_connect {
  die "CONNECT denied in reverse proxy mode"
}

sub on_init {
  my $self = shift;
  die "FATAL: target unspecified" unless $self->target;
  $self->_remote->port(80)  if !$self->_remote->port && $self->_remote->scheme eq 'http';
  $self->_remote->port(443) if !$self->_remote->port && $self->_remote->scheme eq 'https';
  warn "###\n";
  warn "### REVERSE PROXY INITIALIZED: ", $self->_local->to_string, " => ", $self->_remote->to_string, "\n";
  warn "###\n";
}

sub on_request {
  my ($self, $id, $tx, $stash) = @_;

  # fix URL + handle 'Host:' HTTP header
  $tx->req->headers->host($self->_remote->host);
  $tx->req->url->host($self->_remote->host);
  $tx->req->url->port($self->_remote->port);
  $tx->req->url->scheme($self->_remote->scheme);

  # fix referer
  if (my $ref = $tx->req->headers->referrer) {
    my $ref_url =  Mojo::URL->new($ref);
    my $ref_scheme = $ref_url->scheme || $stash->{tls} ? 'https' : 'http';
    my $ref_port   = $ref_url->port || $ref_scheme eq 'https' ? 443 : 80;
    if ( $ref_url->host && $ref_url->host eq $self->_local->host && 
                           $ref_port == $self->_local->port &&
                           $ref_scheme == $self->_local->scheme ) {
      $ref_url->scheme($self->_remote->scheme);
      $ref_url->host($self->_remote->host);
      $ref_url->port($self->_remote->port);
      $ref_url->port(undef) if $ref_url->port == 80  && $ref_url->scheme eq 'http';
      $ref_url->port(undef) if $ref_url->port == 443 && $ref_url->scheme eq 'https';
      $tx->req->headers->referrer($ref_url->to_string);
    }
  }
}

sub on_response {
  my ($self, $id, $tx, $stash) = @_;

  # handle redirects
  if (my $loc = $tx->res->headers->location) {
    my $loc_url = Mojo::URL->new($loc);
    my $loc_scheme = $loc_url->scheme || $stash->{tls} ? 'https' : 'http';
    my $loc_port   = $loc_url->port || $loc_scheme eq 'https' ? 443 : 80;
    if ( $loc_url->host && $loc_url->host eq $self->_remote->host && 
                           $loc_port == $self->_remote->port &&
                           $loc_scheme == $self->_remote->scheme ) {
      $loc_url->scheme($self->_local->scheme);
      $loc_url->host($self->_local->host);
      $loc_url->port($self->_local->port);
      $loc_url->port(undef) if $loc_url->port == 80  && $loc_url->scheme eq 'http';
      $loc_url->port(undef) if $loc_url->port == 443 && $loc_url->scheme eq 'https';   
      $tx->res->headers->location($loc_url->to_string);
    }
  }

  # handle Set-Cookie
  for my $header ($tx->res->headers->header('Set-Cookie')) {
    for (@$header) {
      s/; *secure//i;                 # strip secure flag
      #s/; *HttpOnly//i;               # strip httponly flag
      #s/; *domain=([\.\-a-z0-9]+)//i; # strip domain
    }
  }

}

1;