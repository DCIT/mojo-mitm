package PluginExample;

use Mojo::Base 'Mojo::MITM::Plugin';

### inherited attributes
# proxy - the main proxy object  Mojo::MITM::Proxy instance
#         $self->proxy->log      Mojo::MITM::Logger instance
#         $self->proxy->fake_ca  Mojo::MITM::CA instance
#         $self->proxy->ioloop   see https://metacpan.org/module/Mojo::IOLoop
#         $self->proxy->ua       see https://metacpan.org/module/Mojo::UserAgent

### attributes defined by plugin
# you can override attributes from commandline:
# mojo-mitm -p /path/to/PluginExample.pm,param1=55,param2=66

has param1 => 11;
has param2 => 22;

sub on_init {
  ### called just once when proxy starts
  my $self = shift;
  warn "ON.INIT\n";
  #warn "param1=", $self->param1, "param2=", $self->param2, "\n";
  #$self->proxy->ioloop->recurring(15 => sub { warn "Plugin timer!\n" });
}

sub on_exit {
  ### called just once when proxy is going to shut down
  my $self = shift;
  warn "ON.EXIT\n";
}

sub on_connect {
  my ($self, $id, $tx, $stash) = @_;
  
  ### you can force server TLS certificate to be used for given CONNECT
  #$stash->{server_tls_key} = '/path/to/server.key.pem';
  #$stash->{server_tls_crt} = '/path/to/server.crt.pem';
  
  ### or simply die "..." which turns into "400 Bad Request"
  #die "CONNECT not denied";
}

sub on_request {
  my ($self, $id, $tx, $stash) = @_;
  ### called on every request (except CONNECT) received by the proxy from the client
  # $id    - unique request/response id
  # $tx    - instance of Mojo::Transaction::HTTP - https://metacpan.org/module/Mojo::Transaction
  #            $tx->req ... HTTP request client >>> proxy
  #                         see https://metacpan.org/module/Mojo::Message::Request
  #            $tx->remote_address + $tx->remote_port ... client
  #            $tx->local_address + $tx->local_port   ... proxy listener
  # $stash - HASH reference with extra info related to request
  #          same $stash is passed to the corresponding response
  #          it is handy for storing data for later use in on_response()
  #          by default it is populated with:
  #            $stash->{lsnr_address}   ... proxy listener IP
  #            $stash->{lsnr_port}      ... proxy listener port
  #            $stash->{tls}            ... request got via https 0|1
  #            $stash->{client_address} ... client IP
  #            $stash->{client_port}    ... client port

  ### you can force client TLS certificate to be used for outgoing connection
  #$stash->{client_tls_key} = 'user.key';
  #$stash->{client_tls_crt} = 'user.crt';

  warn "ON.REQUEST[$id]\n";

  ### put some data into $stash
  # $stash->{mydata} = 'Hi!';

  ### remove header
  #$tx->req->headers->remove('If-Modified-Since');
  #$tx->req->headers->remove('If-None-Match');

  ### set header
  #$tx->req->headers->host('fake.host.com');

  ### change URL to target server
  #$tx->req->url->host('fake.host.com');
  #$tx->req->url->scheme('https');

}

sub on_response {
  my ($self, $id, $tx, $stash) = @_;
  ### called on every response the proxy is about to send to the client
  # $id   - unique request/response id
  # $tx    - instance of Mojo::Transaction::HTTP - https://metacpan.org/module/Mojo::Transaction
  #            $tx->req ... HTTP request  - proxy >>> target-server
  #                         see https://metacpan.org/module/Mojo::Message::Request
  #            $tx->res ... HTTP response - target-server >>> proxy
  #                         see https://metacpan.org/module/Mojo::Message::Response
  #            $tx->remote_address + $tx->remote_port ... target-server
  #            $tx->local_address + $tx->local_port   ... proxy (outgoing connection)
  # $stash - HASH reference with extra info related to request/response

  warn "ON.RESPONSE[$id]\n";

  ### get some data from $stash
  # warn "MyData=", $stash->{mydata}, "\n";

  ### patch body
  #my $body = $tx->res->body;
  #$body =~ s/something/somethingelse/;
  #$tx->res->body($body);

  ### patch Set-Cookie
  #for my $header ($tx->res->headers->header('Set-Cookie')) {
  #  s/; *secure//i for @$header;  # strip secure flag
  #}

}

1;