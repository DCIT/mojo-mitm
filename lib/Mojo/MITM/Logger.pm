package Mojo::MITM::Logger;

use Mojo::Base -base;
use Time::Piece 'localtime';
use Term::ReadKey;
use IO::Handle;
use Data::Dump qw(pp quote);

$Data::Dump::TRY_BASE64 = 0;

has verbosity => 2;
has log_file  => undef;
has log_file_handle => undef;

sub new {
  my $self = shift->SUPER::new(@_);
  if (my $f = $self->log_file) {
    open(my $fh, ">>", $f) or die "FATAL: cannot open log file '$f'\n";
    $fh->autoflush;
    $self->log_file_handle($fh);
    warn "-- Logging redirected to '$f'\n";
    #$self->_cut_and_print(localtime->hms . " LOGFILE INIT");
  }
  return $self;
}

sub req {
  my ($self, $id, $tx) = @_;
  my $msg = localtime->hms . " " . sprintf("[%04d] %s", $id, $tx->req->method);
  
  #XXX-FIXME due to maybe-bug in Mojo::Parameters we cannot use: 
  # my $params = $tx->req->params->params;
  #as it converts 'http://my.url/xxx?novalue' to 'http://my.url/xxx?novalue='
  my $p1 = $tx->req->query_params ? Mojo::Parameters->new($tx->req->query_params)->to_hash : {};
  my $p2 = $tx->req->body_params  ? Mojo::Parameters->new($tx->req->body_params)->to_hash  : {};
  my $params = { %$p1, %$p2 };

  my $url = $tx->req->url->to_abs // '?';
  $url = $tx->req->url->host . ':' . $tx->req->url->port if $tx->req->method eq 'CONNECT';

  if ($self->verbosity > 2) {
    #verbosity 3
    $msg .= " $url\n";
    $msg .= " PARAMETERS:\n" if keys %$params;
    for (sort keys %$params) {
      $msg .= " -> $_ = " . pp($params->{$_}) . "\n";
    }
    $msg .= " COOKIES:\n" if @{$tx->req->cookies};
    for my $c (@{$tx->req->cookies}) {
      #$msg .= " -> " . $c->to_string . "\n";
      $msg .= " -> " . $c->name ." = " . $c->value . "\n";
    }
    my @t = map { " -> $_" } split(/\n/, $tx->req->headers->to_string);
    $msg .= " HEADERS:\n" . join("\n", @t) . "\n";
    if ($tx->req->body && length $tx->req->body > 0) {
      my $ct_len = $tx->req->headers->content_length//'';
      my $ct_type = $tx->req->headers->content_type//'';
      my $b = quote(substr($tx->req->body, 0, 320));
      $b .= '...' if length $tx->req->body > 320;
      $msg .= " BODY: len=$ct_len type='$ct_type'\n -> $b\n";
    }
  }
  elsif ($self->verbosity > 1) {
    #verbosity 2
    $msg .= " $url\n";
  }
  else {
    #verbosity 1
    $url =~ s/^([^\?]+).*$/$1/; #XXX-HACK strip query part
    $msg .= " $url";
    $msg .= " (" . join(',', keys %$params) . ")" if keys %$params;
    $msg .= "\n";
  }

  $self->_cut_and_print($msg) if $self->verbosity > 0;
}

sub res {
  my ($self, $id, $duration, $tx) = @_;
  my $ct_len = $tx->res->headers->content_length//'';
  my $ct_type = $tx->res->headers->content_type//'';
  
  my $msg = localtime->hms . " " . sprintf("[%04d] <- %d %s, %dms, len=%s", $id, $tx->res->code, $tx->res->message//'?', $duration*1000, $ct_len);

  if ($self->verbosity > 1) {
    #verbosity 2 + 3
    $msg .= ", redir='" . $tx->res->headers->location . "'" if $tx->res->headers->location;
    $msg .= ", type='$ct_type'" if defined $tx->res->headers->content_type;
    $msg .= "\n";
  }
  if ($self->verbosity > 2) {
    #verbosity 3
    $msg .= " RESPONSE FROM: " . $tx->req->url->to_abs->to_string . "\n";
    my @t = map { " <- $_" } split(/\n/, $tx->res->headers->to_string);
    $msg .= " HEADERS:\n" . join("\n", @t) . "\n";
    if ($tx->res->body && length $tx->res->body > 0) {
      my $b = quote(substr($tx->res->body, 0, 320));
      $b .= '...' if length $tx->res->body > 320;
      $msg .= " BODY: len=$ct_len type='$ct_type'\n <- $b\n";
    }
  }

  $self->_cut_and_print($msg) if $self->verbosity > 0;
}

sub error {
  my ($self, @items) = @_;
  #my $msg = join ('', "### ERR(", localtime->hms, ") ", @items);
  my $msg = join('', "###ERROR: " , @items);
  $self->_cut_and_print($msg, 1) if $self->verbosity > 0;
}

sub warn {
  my ($self, @items) = @_;
  #my $msg = join('', "** warn(" , localtime->hms, ") ", @items);
  my $msg = join('', "WARNING: " , @items);
  $self->_cut_and_print($msg, 1) if $self->verbosity > 1;
}

sub info {
  my ($self, @items) = @_;
  #my $msg = join('', ".. info(" , localtime->hms, ") ", @items);
  my $msg = join('', "INFO: " , @items);
  $self->_cut_and_print($msg, 1) if $self->verbosity > 1;
}

sub _cut_and_print {
  my ($self, $msg, $nocut) = @_;

  if ($self->log_file_handle) {
    $msg =~ s/[\r\n]*$/\n/;
    print {$self->log_file_handle} $msg;
  }
  else {    
    my @lines = split /\n/, $msg;
    my $width;
    eval { ($width) = Term::ReadKey::GetTerminalSize(\*STDOUT); } if -t *STDOUT; # if stdout not redirected take term width  
    if ($width && !$nocut) {
      for (@lines) {
        $_ = substr($_, 0, $width-2) . '>' if length($_) > $width;
      }
    }
    local $| = 1;
    print STDOUT join("\n", @lines) . "\n";
  }
}

1;
