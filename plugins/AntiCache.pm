package AntiCache;

use Mojo::Base 'Mojo::MITM::Plugin';

sub on_request {
  my ($self, $id, $tx, $stash) = @_;
  
  $tx->req->headers->remove('If-Modified-Since');
  $tx->req->headers->remove('If-None-Match');
  $tx->req->headers->header('Cache-Control' => 'no-cache');
  $tx->req->headers->header('Pragma' => 'no-cache');

  #$tx->req->headers->remove('If-Unmodified-Since');
  #$tx->req->headers->remove('If-Match'); 
}

sub on_response {
  my ($self, $id, $tx, $stash) = @_;
  
  $tx->res->headers->remove('Last-Modified');
  $tx->res->headers->remove('Etag');
  $tx->res->headers->remove('Expires');
  $tx->res->headers->header('Cache-Control' => 'no-cache');
  $tx->res->headers->header('Pragma' => 'no-cache');
}

1;