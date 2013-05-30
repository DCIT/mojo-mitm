package Mojo::MITM::Proxy;
use Mojo::Base 'Mojo::EventEmitter';

# the code in this module was derived from Mojo::Server::Daemon

use Carp 'croak';
use Mojo::IOLoop;
use Mojo::URL;
use POSIX;
use Scalar::Util 'weaken';
use Mojo::Transaction::HTTP;
use Mojo::UserAgent;
use Mojo::MITM::CA;
use Mojo::MITM::Logger;
use File::Spec::Functions qw(catdir);
use File::HomeDir;
use File::Slurp;
use Time::HiRes 'time';
use IO::Socket::SSL;

use constant TLS_READ  => IO::Socket::SSL::SSL_WANT_READ();
use constant TLS_WRITE => IO::Socket::SSL::SSL_WANT_WRITE();
use constant DEBUG => $ENV{MOJO_MITM_DEBUG} // 0;

has [qw(backlog group user)];
has inactivity_timeout => 25;
has ioloop => sub { Mojo::IOLoop->singleton };
has listen => sub { ['127.0.0.1:7979'] };
has max_clients  => 1000;
has max_requests => 50;
has no_caching      => 0;
has ca_dir          => sub { catdir(File::HomeDir->my_home, '.mojo-mitm') };
has fake_ca         => sub { Mojo::MITM::CA->new(dir => shift->ca_dir) };
has log             => sub { my $self=shift; Mojo::MITM::Logger->new(verbosity=>$self->verbosity, log_file=>$self->log_file) };
has ua              => sub { Mojo::UserAgent->new };
has verbosity       => 2;
has log_file        => undef;
has clone_crt       => undef;
has request_timeout => 0; # 0 = wait indefinitely
has connect_timeout => 10;
has parent_proxy    => undef; #e.g. 'http://127.0.0.1:8081'
has client_tls_crt  => undef;
has client_tls_key  => undef;
has plugins         => sub { [] };
has plugins_to_load => sub { [] };

sub new {
  my $self = shift->SUPER::new(@_);

  #setup UserAgent
  $self->ua->max_redirects(0)->connect_timeout($self->connect_timeout)->request_timeout($self->request_timeout);
  if ($self->parent_proxy) {
    $self->parent_proxy("http://" . $self->parent_proxy) unless $self->parent_proxy =~ m|^https?://|;
    $self->ua->https_proxy($self->parent_proxy)->http_proxy($self->parent_proxy);
  }

  #normalize listen URLs
  my $l = $self->listen;
  for (@$l) {
    $_ = "http://127.0.0.1:$_" if /^\d+$/;
    $_ = "http://[$_]:7979"    if !m|^https?://| && m|:.*:| && !m|^\[|;
    $_ = "http://$_:7979"      if !m|^https?://| && !m|:|;
    $_ = "http://$_"           if !m|^https?://|;
    my $u = Mojo::URL->new($_);
    $u->port(80)  if !$u->port && $u->scheme eq 'http';
    $u->port(443) if !$u->port && $u->scheme eq 'https';
    $_ = $u->to_string;
  }
  
  #check FakeCA
  die "FATAL: Fake CA not initialized\n" unless defined $self->fake_ca;

  #setup our hadlers
  $self->on(request => \&_handle_request);     #XXX-FIXME is this the correct place for our hacks?
  $self->ioloop->recurring(10 => sub {$self->_print_stats});
  
  #load plugins
  $self->_load_plugin($_, proxy=>$self) for @{$self->plugins_to_load};
  $_->on_init() for @{$self->plugins};
  $self->plugins_to_load([]);

  return $self;
}

sub _load_plugin {
  my $self = shift;
  my $param = shift;

  # split plugin file & params
  my ($file, @tmp) = split /,/, $param;
  my %args;
  for (@tmp) {
      $args{$1}=$2 if /^(.+?)=(.*)$/;
  }
  %args = (%args, @_);

  die "FATAL: plugin file '$file' does not exist\n" unless -f $file;
  my $rv = eval { require $file; 1 };
  die "FATAL: cannot load plugin file '$file'\n", $@ if $@ || !$rv;

  my %already_loaded = map { ref($_) => 1 } @{$self->plugins};
  my @pkgs = grep { /^package\s+(\S+?);/ } read_file($file);
  die "FATAL: no package definition in '$file'\n" unless @pkgs;

  my ($module) = $pkgs[0] =~ /^package\s+(\S+?);/;

  my $o = $module->new(%args) or die "FATAL: $module->new failed";
  die "FATAL: plugin '$file' is not based 'Mojo::MITM::Plugin'\n" unless $o->isa('Mojo::MITM::Plugin');

  push @{$self->plugins}, $o;
  warn "-- Plugin '$module' loaded from file '$file'\n";
}


sub _new_connection {
  my ($self, $stream, $id, $tls) = @_;
  warn "-- [id:", substr($id,0,6), "] _new_connection peer=@{[$stream->handle->peerhost]}\n" if DEBUG;

  # Add new connection
  my $c = $self->{connections}{$id} = {tls => $tls};

  # Inactivity timeout
  $stream->timeout($self->inactivity_timeout);

  # Events
  $stream->on(read    => sub { $self->_read($id => pop) });
  $stream->on(timeout => sub { $self->log->error("stream[$id]: Inactivity timeout") if $c->{tx} });
  $stream->on(close   => sub { $self->_close($id) });
  $stream->on(error   => sub {
                           return unless $self;
                           $self->log->error("stream[$id] failure: ", pop);
                           $self->_close($id);
                         }
  );
}

sub _resume_tx {
  my ($self, $cur_id, $duration, $tx, $code, $message) = @_;
  $tx->res->code($code) if defined $code;
  $tx->res->message($message) if defined $message;
  $self->log->res($cur_id, $duration, $tx);
  $tx->resume;
}

sub _handle_request {
  my ($self, $tx) = @_;

  state $counter = 0;
  my $cur_id = ++$counter;
  $self->log->req($cur_id, $tx);

  my $cur_start_time = time;
  my $method = $tx->req->method;
  my $absurl = $tx->req->url->to_abs;
  my $host   = $tx->req->url->host;
  my $port   = $tx->req->url->port;
  my $conn   = $self->{connections}{$tx->connection};

  my %stash = (
        lsnr_address   => $tx->local_address,
        lsnr_port      => $tx->local_port,
        client_address => $tx->remote_address,
        client_port    => $tx->remote_port,
        client_tls_key => $self->client_tls_key,
        client_tls_crt => $self->client_tls_crt,
  );
  $stash{tls} = ($conn->{tls}{via_connect} ? 'connect' : 'direct') if $conn->{tls};

  if (ref $tx eq 'Mojo::Transaction::WebSocket') {
    $self->log->error("Mojo::MITM::Proxy::_handle_request does not support WebSockets!!!"); 
    ### #XXX-TODO
    # warn "XXX: ws.url=", $absurl->to_string, "\n";
    # $tx->on(text    => sub { my ($ws, $bytes) = @_; warn "XXX: text='$bytes'\n" });
    # $tx->on(message => sub { my ($ws, $msg)   = @_; warn "XXX: msg='$msg'\n" });
    # $tx->on(binary  => sub { my ($ws, $bytes) = @_; warn "XXX: binary='$bytes'\n" });
    # $self->_resume_tx($cur_id, time-$cur_start_time, $tx, 101, 'Upgraded');
    return;
  }

  if ($method =~ /(OPTIONS|GET|HEAD|POST|PUT|DELETE)/) { #not sure about TRACE (disabling for now)

    my $newtx = Mojo::Transaction::HTTP->new;
    $newtx->req($tx->req->clone);
    $newtx->req->url($absurl);
    $newtx->remote_address($tx->remote_address);
    $newtx->remote_port($tx->remote_port);
    $newtx->local_address($tx->local_address);
    $newtx->local_port($tx->local_port);

    # properly handle SSL connections going via CONNECT
    if ($conn->{tls} && !$conn->{tls}{direct}) {
      $newtx->req->url->scheme('https');
      if (!defined $newtx->req->url->host || !defined $newtx->req->url->port) {
        $newtx->req->url->host($conn->{tls}{connect_host});
        $newtx->req->url->port($conn->{tls}{connect_port});
      }
    }

    # plugins - patch request
    eval { $_->on_request($cur_id, $newtx, \%stash) for @{$self->plugins} };
    if ($@) {
      $self->log->error("Plugin/on_request died: $@");
      $self->_resume_tx($cur_id, time-$cur_start_time, $tx, 400, 'Bad Request');
      return;
    }
    # force Content-Length recalculation
    if ($newtx->req->headers->content_length && length($newtx->req->body) != $newtx->req->headers->content_length) {
      $newtx->req->content->headers->remove('Content-Length');
      $newtx->req->fix_headers;
    }
    # check for forced response
    if ($newtx->res->code && $newtx->res->message) {
      $self->log->info('Some plugin [on_request] forced direct response');
      $tx->res($newtx->res);
      $self->_resume_tx($cur_id, time-$cur_start_time, $tx);
      return;
    }

    # remove proxy request related headers
    $newtx->req->content->headers->remove('Proxy-Connection');
    $newtx->req->content->headers->remove('Proxy-Authenticate');
    $newtx->req->content->headers->remove('Proxy-Authorization');
    $newtx->req->proxy(undef);

    if ($stash{client_tls_key} && $stash{client_tls_crt}) {
      $self->ua->cert($stash{client_tls_crt})->key($stash{client_tls_key});
    }
    
    # execute the request
    my $rv = $self->ua->start($newtx => sub {
        my ($ua, $uatx) = @_;
        if ($uatx->error && !$uatx->res->code) {
          $tx->res->code(200)->message('OK')->body("PROXY ERROR: " . $uatx->error);
          $tx->res->headers->content_type('text/plain');
          $self->log->error("request[$cur_id] failure: " . $uatx->error);
        }
        else {
          #plugins - patch response
          eval { $_->on_response($cur_id, $uatx, \%stash) for @{$self->plugins} };
          if ($@) {
            $self->log->error("Plugin/res died: $@");
            $tx->res->code(400)->message('Bad Request')->body('');
          }
          #force Content-Length recalculation
          if ($uatx->res->headers->content_length && length($uatx->res->body) != $uatx->res->headers->content_length) {
            $uatx->res->content->headers->remove('Content-Length');
            $uatx->res->fix_headers;
          }
          #copy response
          $tx->res($uatx->res);
        }

        $self->_resume_tx($cur_id, time-$cur_start_time, $tx);
    });
  }
  elsif ($method eq 'CONNECT') {

    # plugins - patch CONNECT request
    eval { $_->on_connect($cur_id, $tx, \%stash) for @{$self->plugins} };
    if ($@) {
      $self->log->error("Plugin/on_connect died: $@");
      $self->_resume_tx($cur_id, time-$cur_start_time, $tx, 400, 'Bad Request');
      return;
    }
    # force Content-Length recalculation
    if ($tx->req->headers->content_length && length($tx->req->body) != $tx->req->headers->content_length) {
      $tx->req->content->headers->remove('Content-Length');
      $tx->req->fix_headers;
    }
    # check for forced response
    if ($tx->res->code && $tx->res->message) {
      $self->log->info('Some plugin [on_connect] forced direct response');
      $tx->res($tx->res);
      $self->_resume_tx($cur_id, time-$cur_start_time, $tx);
      return;
    }

    $host = $tx->req->url->host;
    $port = $tx->req->url->port;

    if ($host && $port) {
    
      if ($stash{server_tls_crt} && $stash{server_tls_key}) {
        $conn->{tls}{tls_crt} = $stash{server_tls_crt};
        $conn->{tls}{tls_key} = $stash{server_tls_key};
      }
      elsif ($self->clone_crt) {
        # tries to clone as much information from the original certificate as possible
        ($conn->{tls}{tls_crt}, $conn->{tls}{tls_key}) = $self->fake_ca->get_cert($host, $port);
      }
      else {
        # creates only a simple face cert with CN=<hostname>
        ($conn->{tls}{tls_crt}, $conn->{tls}{tls_key}) = $self->fake_ca->get_cert($host);
      }

      $conn->{tls}{connect_host} = $host;
      $conn->{tls}{connect_port} = $port;
      $conn->{tls}{via_connect}  = 1;
      $conn->{connect_tls_request} = 1;

      $self->_resume_tx($cur_id, time-$cur_start_time, $tx, 200, 'OK');
    }
    else {
      $self->log->error("invalid CONNECT request");
      $self->_resume_tx($cur_id, time-$cur_start_time, $tx, 400, 'Bad Request');
    }
  }
  else {
    $self->log->error("method '$method' not supported");
    $self->_resume_tx($cur_id, time-$cur_start_time, $tx, 501, 'Not Implemented');
  }
}

sub _tls {
  my ($self, $handle, $id, $tls) = @_;

  if ($handle->accept_SSL) {
    $self->ioloop->reactor->remove($handle);
    delete $self->{handles}{$handle};
    my $stream = Mojo::IOLoop::Stream->new($handle);
    my $id = $self->ioloop->stream($stream);
    $self->_new_connection($stream, $id, $tls);
    return;
  }

  # Switch between reading and writing
  my $err = $IO::Socket::SSL::SSL_ERROR;
  if    ($err == TLS_READ)  { $self->ioloop->reactor->watch($handle, 1, 0) }
  elsif ($err == TLS_WRITE) { $self->ioloop->reactor->watch($handle, 1, 1) }
}

sub _tls_upgrade_on_connect {
  my ($self, $id) = @_;
  # handle TLS via CONNECT request
  return unless $self->{connections}{$id}{connect_tls_request};
  
  my %ssl_opts = (
        #verify_hostname    => 0,
        SSL_verify_mode    => 0,
        SSL_startHandshake => 0, # just upgrade the socket, keep non-blocking behaviour
        SSL_server         => 1,
        SSL_key_file       => $self->{connections}{$id}{tls}{tls_key},
        SSL_cert_file      => $self->{connections}{$id}{tls}{tls_crt},
        SSL_error_trap     => sub {
                                my ($socket, $err) = @_;
                                $err =~ s/[\r\n]+$//;
                                $self->log->error("SSL_error_trap: $err");
                                return unless my $handle = delete $self->{handles}{$socket};
                                $self->ioloop->reactor->remove($handle);
                                $handle->close;
                              },
  );

  #XXX-FIXME not sure if the following part is correct
  # based on UserAgent's _connect_proxy()
  my $handle = $self->ioloop->stream($id)->steal_handle;
  my $c      = delete $self->{connections}{$id};
  $self->ioloop->remove($id);

  $handle = IO::Socket::SSL->start_SSL($handle, %ssl_opts);
  $self->ioloop->reactor->io($handle => sub { $self->_tls($handle, $id, $c->{tls}) });
  $self->{handles}{$handle} = $handle;
}

sub _print_stats {
  my $self = shift;
  state $last_count = 0;
  my $count = scalar(keys %{$self->{connections}});
  $self->log->info("$count active connection(s)") unless $last_count == 0 && $count == 0;
  $last_count = $count;
}

sub DESTROY {
  my $self = shift;
  return unless my $loop = $self->ioloop;
  $self->_remove($_) for keys %{$self->{connections} || {}};
  $loop->remove($_) for @{$self->{acceptors} || []};
}

sub run {
  my $self = shift;

  # Signals
  $SIG{INT} = $SIG{TERM} = sub {
    $_->on_exit() for @{$self->plugins};
    warn "-- Gonna quit!\n";
    exit 0;
  };

  # Change user/group and start accepting connections
  $self->start->setuidgid->ioloop->start;
}

sub setuidgid {
  my $self = shift;

  # Group
  if (my $group = $self->group) {
    croak qq{Group "$group" does not exist}
      unless defined(my $gid = (getgrnam($group))[2]);
    POSIX::setgid($gid) or croak qq{Can't switch to group "$group": $!};
  }

  # User
  if (my $user = $self->user) {
    croak qq{User "$user" does not exist}
      unless defined(my $uid = (getpwnam($self->user))[2]);
    POSIX::setuid($uid) or croak qq{Can't switch to user "$user": $!};
  }

  return $self;
}

sub start {
  my $self = shift;

  # Resume accepting connections
  my $loop = $self->ioloop;
  if (my $acceptors = $self->{acceptors}) {
    push @$acceptors, $loop->acceptor(delete $self->{servers}{$_})
      for keys %{$self->{servers}};
  }

  # Start listening
  else { $self->_listen($_) for @{$self->listen} }
  $loop->max_connections($self->max_clients);

  return $self;
}

sub stop {
  my $self = shift;

  # Suspend accepting connections but keep listen sockets open
  my $loop = $self->ioloop;
  while (my $id = shift @{$self->{acceptors}}) {
    my $server = $self->{servers}{$id} = $loop->acceptor($id);
    $loop->remove($id);
    $server->stop;
  }

  return $self;
}

sub _build_tx {
  my ($self, $id, $c) = @_;

  my $tx = Mojo::Transaction::HTTP->new()->connection($id);

  my $handle = $self->ioloop->stream($id)->handle;
  $tx->local_address($handle->sockhost)->local_port($handle->sockport);
  $tx->remote_address($handle->peerhost)->remote_port($handle->peerport);
  $tx->req->url->base->scheme('https') if $c->{tls};

  # Handle upgrades and requests
  weaken $self;
  $tx->on(finish => sub {$self->_tls_upgrade_on_connect($id)} );
  $tx->on(
    upgrade => sub {
      my ($tx, $ws) = @_;
      $ws->server_handshake;
      $self->{connections}{$id}{ws} = $ws;
    }
  );
  $tx->on(
    request => sub {
      my $tx = shift;
      $self->emit(request => $self->{connections}{$id}{ws} || $tx);
      $tx->on(resume => sub { $self->_write($id) });
    }
  );

  # Kept alive if we have more than one request on the connection
  return ++$c->{requests} > 1 ? $tx->kept_alive(1) : $tx;
}

sub _close {
  my ($self, $id) = @_;

  # Finish gracefully
  if (my $tx = $self->{connections}{$id}{tx}) { $tx->server_close }

  delete $self->{connections}{$id};
}

sub _finish {
  my ($self, $id, $tx) = @_;

  # Always remove connection for WebSockets
  return $self->_remove($id) if $tx->is_websocket;

  # Finish transaction
  $tx->server_close;

  # Upgrade connection to WebSocket
  my $c = $self->{connections}{$id};
  if (my $ws = $c->{tx} = delete $c->{ws}) {

    # Successful upgrade
    if ($ws->res->code eq '101') {
      weaken $self;
      $ws->on(resume => sub { $self->_write($id) });
    }

    # Failed upgrade
    else {
      delete $c->{tx};
      $ws->server_close;
    }
  }

  # Close connection if necessary
  my $req = $tx->req;
  return $self->_remove($id) if $req->error || !$tx->keep_alive;

  # Build new transaction for leftovers
  return unless length(my $leftovers = $req->content->leftovers);
  $tx = $c->{tx} = $self->_build_tx($id, $c);
  $tx->server_read($leftovers);
}

sub _ctx_sni_callback {
  my ($self, $ctx, $port) = @_;
  Net::SSLeay::CTX_set_tlsext_servername_callback($ctx, sub {
        my $ssl = shift;
        my $h = Net::SSLeay::get_servername($ssl) or return;
        if (!$self->{ctx_cache}{$h}) {
          $self->{ctx_cache}{$h} = Net::SSLeay::CTX_new or return;
          my ($crt, $key) = $self->fake_ca->get_cert($h, $self->clone_crt ? $port : undef); #XXX-FIXME clone_crt hack
          Net::SSLeay::set_cert_and_key($self->{ctx_cache}{$h}, $crt, $key) or return;
        }
        Net::SSLeay::set_SSL_CTX($ssl, $self->{ctx_cache}{$h}) if $self->{ctx_cache}{$h};
  });
}

sub _listen {
  my ($self, $listen) = @_;

  my $url     = Mojo::URL->new($listen);
  my $query   = $url->query;
  my $options = {
    address  => $url->host,
    backlog  => $self->backlog,
    port     => $url->port,
    tls_ca   => scalar $query->param('ca'),
    tls_cert => scalar $query->param('cert'),
    tls_key  => scalar $query->param('key')
  };
  if ($url->protocol eq 'https') {
    if (!$options->{tls_cert} || !$options->{tls_key}) {
      ($options->{tls_cert}, $options->{tls_key}) = $self->fake_ca->get_cert($url->host);
    }
    if (!$query->param('nosni')) {
      #XXX-FIXME ugly workaround for setting SNI callback
      IO::Socket::SSL::set_ctx_defaults(SSL_create_ctx_callback => sub { $self->_ctx_sni_callback($_[0],$url->port) });
    }
  }
  my $verify = $query->param('verify');
  $options->{tls_verify} = hex $verify if defined $verify;
  delete $options->{address} if $options->{address} eq '*';
  my $tls = $options->{tls} = $url->protocol eq 'https' ? 1 : undef;

  weaken $self;
  my $id = $self->ioloop->server(
    $options => sub {
      my ($loop, $stream, $id) = @_;
      $self->_new_connection($stream, $id, $tls ? {direct=>1} : undef);
    }
  );
  push @{$self->{acceptors} ||= []}, $id;

  die "FATAL: udenfined listening port [$listen]\n" unless $url->port;
  die "FATAL: udenfined listening address [$listen]\n" unless $url->host;
  (my $lsn = $url->to_string) =~ s!(^https?://)?([^/]+).*$!$1$2!;
  warn "-- Listening at $lsn\n";
}

sub _read {
  my ($self, $id, $chunk) = @_;

  # Make sure we have a transaction and parse chunk
  return unless my $c = $self->{connections}{$id};
  my $tx = $c->{tx} ||= $self->_build_tx($id, $c);
  warn "-- Server <<< Client (@{[$tx->req->url->to_abs]})\n$chunk\n" if DEBUG;
  $tx->server_read($chunk);

  # Last keep-alive request or corrupted connection
  $tx->res->headers->connection('close')
    if (($c->{requests} || 0) >= $self->max_requests) || $tx->req->error;

  # Finish or start writing
  if ($tx->is_finished) { $self->_finish($id, $tx) }
  elsif ($tx->is_writing) { $self->_write($id) }
}

sub _remove {
  my ($self, $id) = @_;
  $self->ioloop->remove($id);
  $self->_close($id);
}

sub _write {
  my ($self, $id) = @_;

  # Not writing
  return unless my $c  = $self->{connections}{$id};
  return unless my $tx = $c->{tx};
  return unless $tx->is_writing;

  # Get chunk and write
  return if $c->{writing}++;
  my $chunk = $tx->server_write;
  delete $c->{writing};
  warn "-- Server >>> Client (@{[$tx->req->url->to_abs]})\n$chunk\n" if DEBUG;
  my $stream = $self->ioloop->stream($id)->write($chunk);

  # Finish or continue writing
  weaken $self;
  my $cb = sub { $self->_write($id) };
  if ($tx->is_finished) {
    if ($tx->has_subscribers('finish')) {
      $cb = sub { $self->_finish($id, $tx) }
    }
    else {
      $self->_finish($id, $tx);
      return unless $c->{tx};
    }
  }
  $stream->write('' => $cb);
}

1;
