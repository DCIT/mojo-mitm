package Mojo::MITM::CA;

use Mojo::Base -base;

use File::Slurp qw(write_file read_file);
use File::Spec::Functions qw(catfile catdir);
use Mojo::JSON;
use Net::SSLeay;
use Time::Piece;

BEGIN {
  Net::SSLeay::initialize();
}

### attributes

has verbosity => 1;
has dir       => sub { '.FakeCA' };
has _cache    => sub { catdir(shift->dir,  'CA_cache') };
has _ca_crt   => sub { catfile(shift->dir, 'CA_MITM.crt') };
has _ca_key   => sub { catfile(shift->dir, 'CA_MITM.key') };
has _json     => sub { catfile(shift->_cache, '_cache_.json') };
has _data     => undef;

### methods

sub new {
  my $self = shift->SUPER::new(@_);

  die "FATAL: undefined dir attribute" unless $self->dir;
  for ($self->dir, $self->_cache) {
    next if -d $_;
    warn "-- Creating directory '$_'\n";
    mkdir $_ or die "FATAL: cannot create directory '$_': $!";
  }

  if (!-f $self->_ca_crt || !-f $self->_ca_key) {
    warn "-- Generating new CA certificate + key\n";
    $self->_create_ca_cert($self->_ca_crt, $self->_ca_key);
  }
  warn "-- Using fake CA '", $self->_ca_crt, "'\n";

  if (-f $self->_json) {
    my $json  = Mojo::JSON->new;
    my $cache = $json->decode(read_file($self->_json));
    $self->_data($cache);
  }
  else {
    $self->_data( {_next_serial_=>1+(int(rand(0xFFFF))<<16)} );
  }

  return $self;
}

sub get_cert {
  my ($self, $host, $port) = @_;
  my $key = $host . '_' . ($port//'any');
  if (!defined $self->_data->{$key}) {
    $self->_data->{$key}->{cert}      = catfile($self->_cache, "$key.crt.pem");
    $self->_data->{$key}->{privkey}   = catfile($self->_cache, "$key.key.pem");
    $self->_data->{$key}->{serialnum} = $self->_data->{_next_serial_}++;
    if ($port) {
      #XXX-TODO BEWARE this is blocking!!!!
      $self->_clone_server_cert($host, $port, $self->_data->{$key}->{cert}, $self->_data->{$key}->{privkey}, $self->_data->{$key}->{serialnum});
    }
    else {
      $self->_create_server_cert($host, $self->_data->{$key}->{cert}, $self->_data->{$key}->{privkey}, $self->_data->{$key}->{serialnum});
    }
    my $json  = Mojo::JSON->new;
    write_file($self->_json, $json->encode($self->_data));
  }
  return (
    $self->_data->{$key}->{cert},
    $self->_data->{$key}->{privkey},
    $self->_data->{$key}->{serialnum},
  );
}

sub _create_ca_cert {
  my ($self, $filename_crt, $filename_key) = @_;

  #generate RSA key pair
  my $pk   = Net::SSLeay::EVP_PKEY_new();
  my $rsa  = Net::SSLeay::RSA_generate_key(2048, 0x10001); # 2048 bits; 0x10001 = RSA_F4
  Net::SSLeay::EVP_PKEY_assign_RSA($pk,$rsa);

  #create new cert
  my $new_cert  = Net::SSLeay::X509_new();
  Net::SSLeay::X509_set_pubkey($new_cert,$pk);

  #set common name
  my $serial = int rand 0xFFF;
  my $name = Net::SSLeay::X509_get_subject_name($new_cert);
  Net::SSLeay::X509_NAME_add_entry_by_txt($name, "CN", &Net::SSLeay::MBSTRING_ASC, 'MITM CA');
  Net::SSLeay::X509_NAME_add_entry_by_txt($name, "OU", &Net::SSLeay::MBSTRING_ASC, sprintf("Mojo::MITM 0x%X", $serial));
  Net::SSLeay::X509_NAME_add_entry_by_txt($name, "O",  &Net::SSLeay::MBSTRING_ASC, 'This CA is a fake!');
  Net::SSLeay::X509_NAME_add_entry_by_txt($name, "C",  &Net::SSLeay::MBSTRING_ASC, 'US');

  #set basic attributes
  my $sn = Net::SSLeay::X509_get_serialNumber($new_cert);
  Net::SSLeay::ASN1_INTEGER_set($sn, $serial);
  Net::SSLeay::X509_set_version($new_cert, 2);
  Net::SSLeay::X509_set_issuer_name($new_cert, $name);

  #calculate validity of the new certificate
  my $now_time = Time::Piece::gmtime;
  my $now_isotime        = $now_time->datetime . "+0000";
  my $new_cert_notafter  = $now_time->add(80*365*24*60*60)->datetime . "+0000";  # +80years
  my $new_cert_notbefore = $now_time->add(-11*24*60*60)->datetime . "+0000";     # -11days

  #set validity
  Net::SSLeay::P_ASN1_TIME_set_isotime(Net::SSLeay::X509_get_notAfter($new_cert), $new_cert_notafter);
  Net::SSLeay::P_ASN1_TIME_set_isotime(Net::SSLeay::X509_get_notBefore($new_cert), $new_cert_notbefore);

  #set extensions
  Net::SSLeay::P_X509_add_extensions($new_cert, $new_cert,
        &Net::SSLeay::NID_key_usage => 'keyCertSign,cRLSign',
        &Net::SSLeay::NID_subject_key_identifier => 'hash',
        &Net::SSLeay::NID_basic_constraints => 'critical,CA:TRUE',
        &Net::SSLeay::NID_netscape_cert_type => 'sslCA, emailCA, objCA',
  );

  #sign by CA privkey
  my $sha1_digest = Net::SSLeay::EVP_get_digestbyname("sha1") or die "FATAL: SHA1 not available";
  Net::SSLeay::X509_sign($new_cert, $pk, $sha1_digest);

  #write cert+key to files
  write_file($filename_crt, Net::SSLeay::PEM_get_string_X509($new_cert));
  write_file($filename_key, Net::SSLeay::PEM_get_string_PrivateKey($pk));

  return 1;
}

sub _create_server_cert {
  my ($self, $hostname, $filename_crt, $filename_key, $serialnum) = @_;
  die "FATAL: undefined common name" unless $hostname;

  #load CA cert+key
  my $ca_cert = Net::SSLeay::PEM_read_bio_X509(Net::SSLeay::BIO_new_file($self->_ca_crt, 'r'));
  my $ca_pk = Net::SSLeay::PEM_read_bio_PrivateKey(Net::SSLeay::BIO_new_file($self->_ca_key, 'r'));
  my $ca_cert_notafter  = Net::SSLeay::P_ASN1_TIME_get_isotime(Net::SSLeay::X509_get_notAfter($ca_cert));
  my $ca_cert_notbefore = Net::SSLeay::P_ASN1_TIME_get_isotime(Net::SSLeay::X509_get_notBefore($ca_cert));

  #generate RSA key pair
  my $pk   = Net::SSLeay::EVP_PKEY_new();
  my $rsa  = Net::SSLeay::RSA_generate_key(2048, 0x10001); # 2048 bits; 0x10001 = RSA_F4
  Net::SSLeay::EVP_PKEY_assign_RSA($pk,$rsa);

  #create new cert
  my $new_cert  = Net::SSLeay::X509_new();
  Net::SSLeay::X509_set_pubkey($new_cert,$pk);

  #set common name
  my $name = Net::SSLeay::X509_get_subject_name($new_cert);
  Net::SSLeay::X509_NAME_add_entry_by_txt($name, "CN", &Net::SSLeay::MBSTRING_ASC, $hostname);
  #Net::SSLeay::X509_NAME_add_entry_by_txt($name, "OU", &Net::SSLeay::MBSTRING_ASC, 'Mojo::MITM');
  #Net::SSLeay::X509_NAME_add_entry_by_txt($name, "O", &Net::SSLeay::MBSTRING_ASC, 'This certificate is a fake!');
  #Net::SSLeay::X509_NAME_add_entry_by_txt($name, "C",  &Net::SSLeay::MBSTRING_ASC, 'US');

  #set basic attributes
  my $sn = Net::SSLeay::X509_get_serialNumber($new_cert);
  Net::SSLeay::ASN1_INTEGER_set($sn, $serialnum);
  Net::SSLeay::X509_set_version($new_cert, 2);
  Net::SSLeay::X509_set_issuer_name($new_cert, Net::SSLeay::X509_get_subject_name($ca_cert));

  #calculate validity of the new certificate
  my $now_time = Time::Piece::gmtime;
  my $now_isotime        = $now_time->datetime . "+0000";
  my $new_cert_notafter  = $now_time->add(10*365*24*60*60)->datetime . "+0000"; # +10years
  my $new_cert_notbefore = $now_time->add(-10*24*60*60)->datetime . "+0000";    # -10days

  $new_cert_notafter  = $ca_cert_notafter  if _compare_iso_time($ca_cert_notafter, $new_cert_notafter)<0;
  $new_cert_notbefore = $ca_cert_notbefore if _compare_iso_time($new_cert_notbefore, $ca_cert_notbefore)<0;
  if (_compare_iso_time($now_isotime, $ca_cert_notbefore)<0 || _compare_iso_time($ca_cert_notafter, $now_isotime)<0) {
    warn "WARNING: CA invalid (current time out of valitity range)";
  }

  #set validity
  Net::SSLeay::P_ASN1_TIME_set_isotime(Net::SSLeay::X509_get_notAfter($new_cert), $new_cert_notafter);
  Net::SSLeay::P_ASN1_TIME_set_isotime(Net::SSLeay::X509_get_notBefore($new_cert), $new_cert_notbefore);

  #set extensions
  Net::SSLeay::P_X509_add_extensions($new_cert, $ca_cert,
        &Net::SSLeay::NID_key_usage => 'digitalSignature,keyEncipherment',
        &Net::SSLeay::NID_subject_key_identifier => 'hash',
        &Net::SSLeay::NID_authority_key_identifier => 'keyid',
        &Net::SSLeay::NID_authority_key_identifier => 'issuer',
        &Net::SSLeay::NID_basic_constraints => 'CA:FALSE',
        &Net::SSLeay::NID_ext_key_usage => 'serverAuth,clientAuth',
        &Net::SSLeay::NID_netscape_cert_type => 'server',
        &Net::SSLeay::NID_subject_alt_name => "DNS:$hostname",
  );

  #sign by CA privkey
  my $sha1_digest = Net::SSLeay::EVP_get_digestbyname("sha1") or die "FATAL: SHA1 not available";
  Net::SSLeay::X509_sign($new_cert, $ca_pk, $sha1_digest);

  #write cert+key to files
  write_file($filename_crt, Net::SSLeay::PEM_get_string_X509($new_cert));
  write_file($filename_key, Net::SSLeay::PEM_get_string_PrivateKey($pk));

  return 1;
}

sub _clone_server_cert {
  my ($self, $host, $port, $filename_crt, $filename_key, $serialnum) = @_;

  #XXX-FIXME this is blocking!!!
  warn("Info: Gonna make blocking call to fake_ca->get_cert($host, $port)\n");

  my $ctx = Net::SSLeay::CTX_new();
  Net::SSLeay::CTX_set_options($ctx, &Net::SSLeay::OP_ALL);
  my $ssl = Net::SSLeay::new($ctx);
  my $socket = IO::Socket::IP->new( PeerAddr=>$host, PeerPort=>$port ) or die "FATAL: connect [$host:$port] failed";
  Net::SSLeay::set_fd($ssl, $socket->fileno);
  Net::SSLeay::connect($ssl);
  my $server_cert = Net::SSLeay::get_peer_certificate($ssl);

  $self->_clone_x509_cert($server_cert, $filename_crt, $filename_key, $serialnum);

  Net::SSLeay::CTX_free($ctx);
  Net::SSLeay::free($ssl);
  $socket->close;
}

sub _clone_x509_cert {
  my ($self, $server_cert, $filename_crt, $filename_key, $serialnum) = @_;

  die "FATAL: no server cert" unless $server_cert;

  #load CA cert+key
  my $ca_cert = Net::SSLeay::PEM_read_bio_X509(Net::SSLeay::BIO_new_file($self->_ca_crt, 'r'));
  my $ca_pk = Net::SSLeay::PEM_read_bio_PrivateKey(Net::SSLeay::BIO_new_file($self->_ca_key, 'r'));
  my $ca_cert_notafter  = Net::SSLeay::P_ASN1_TIME_get_isotime(Net::SSLeay::X509_get_notAfter($ca_cert));
  my $ca_cert_notbefore = Net::SSLeay::P_ASN1_TIME_get_isotime(Net::SSLeay::X509_get_notBefore($ca_cert));

  my @nids;
  my $subject = Net::SSLeay::X509_get_subject_name($server_cert);
  my $count = Net::SSLeay::X509_NAME_entry_count($subject);
  for my $i (0..$count-1) {
    my $e = Net::SSLeay::X509_NAME_get_entry($subject, $i);
    my $o = Net::SSLeay::X509_NAME_ENTRY_get_object($e);
    my $d = Net::SSLeay::X509_NAME_ENTRY_get_data($e);
    #warn "XXX: oid=", Net::SSLeay::OBJ_obj2txt($o,0);
    #next unless Net::SSLeay::OBJ_obj2txt($o,0) =~ /^(commonName|organizationName|organizationalUnitName)$/;
    push @nids, { obj=>$o, data=>Net::SSLeay::P_ASN1_STRING_get($d) };
  }

  my $pk   = Net::SSLeay::EVP_PKEY_new();
  my $rsa  = Net::SSLeay::RSA_generate_key(2048, 0x10001); # 0x10001 = RSA_F4
  Net::SSLeay::EVP_PKEY_assign_RSA($pk,$rsa);

  my $new_cert  = Net::SSLeay::X509_new();
  Net::SSLeay::X509_set_pubkey($new_cert,$pk);
  my $name = Net::SSLeay::X509_get_subject_name($new_cert);
  for (@nids) {
    Net::SSLeay::X509_NAME_add_entry_by_OBJ($name, $_->{obj}, 0x1000, $_->{data}, -1, 0); # 0x1000 = MBSTRING_UTF8
  }

  #set basic attributes
  my $ver = Net::SSLeay::X509_get_version($server_cert);
  Net::SSLeay::X509_set_version($new_cert, $ver);

  #my $serial_hex = Net::SSLeay::P_ASN1_INTEGER_get_hex(Net::SSLeay::X509_get_serialNumber($server_cert));
  my $sn = Net::SSLeay::X509_get_serialNumber($new_cert);
  Net::SSLeay::ASN1_INTEGER_set($sn, $serialnum);

  Net::SSLeay::X509_set_issuer_name($new_cert, Net::SSLeay::X509_get_subject_name($ca_cert));

  #calculate validity of the new certificate
  my $now_time = Time::Piece::gmtime;
  my $now_isotime        = $now_time->datetime . "+0000";
  my $new_cert_notafter  = $now_time->add(10*365*24*60*60)->datetime . "+0000"; # +10years
  my $new_cert_notbefore = $now_time->add(-10*24*60*60)->datetime . "+0000";    # -10days

  $new_cert_notafter  = $ca_cert_notafter  if _compare_iso_time($ca_cert_notafter, $new_cert_notafter)<0;
  $new_cert_notbefore = $ca_cert_notbefore if _compare_iso_time($new_cert_notbefore, $ca_cert_notbefore)<0;
  if (_compare_iso_time($now_isotime, $ca_cert_notbefore)<0 || _compare_iso_time($ca_cert_notafter, $now_isotime)<0) {
    warn "WARNING: CA invalid (current time out of valitity range)";
  }

  #set validity
  Net::SSLeay::P_ASN1_TIME_set_isotime(Net::SSLeay::X509_get_notAfter($new_cert), $new_cert_notafter) or warn "Cannot set 'notAfter'";
  Net::SSLeay::P_ASN1_TIME_set_isotime(Net::SSLeay::X509_get_notBefore($new_cert), $new_cert_notbefore) or warn "Cannot set 'notBefore'";

  #copy all subjectAltNames
  my @altnames = Net::SSLeay::X509_get_subjectAltNames($server_cert);
  my $all_alt_names = '';
  while (@altnames) {
    my ($t,$v) = (shift @altnames, shift @altnames);
    if ($t == 2) {
      $all_alt_names .= "," if $all_alt_names;
      $all_alt_names .= "DNS:$v"
    }
  }

  #set extensions
  Net::SSLeay::P_X509_add_extensions($new_cert, $ca_cert,
        &Net::SSLeay::NID_key_usage => 'digitalSignature,keyEncipherment',
        &Net::SSLeay::NID_subject_key_identifier => 'hash',
        &Net::SSLeay::NID_authority_key_identifier => 'keyid',
        &Net::SSLeay::NID_authority_key_identifier => 'issuer',
        &Net::SSLeay::NID_basic_constraints => 'CA:FALSE',
        &Net::SSLeay::NID_ext_key_usage => 'serverAuth,clientAuth',
        &Net::SSLeay::NID_netscape_cert_type => 'server',
        ($all_alt_names ? (&Net::SSLeay::NID_subject_alt_name => $all_alt_names) : ()),
  );

  #sign by ca privkey
  my $sha1_digest = Net::SSLeay::EVP_get_digestbyname("sha1") or die "SHA1 not available";
  Net::SSLeay::X509_sign($new_cert, $ca_pk, $sha1_digest);

  write_file($filename_crt, Net::SSLeay::PEM_get_string_X509($new_cert));
  write_file($filename_key, Net::SSLeay::PEM_get_string_PrivateKey($pk));

  return 1;
}

### helper function (not method)

sub _compare_iso_time {
  my ($dt1, $dt2) = @_;

  #we support only zone names: Z GMT UTC and zone shifts +NNNN/-NNNN (which seems to be OK for now)
  $dt1 = substr($dt1, 0, 19) . "+0000" if $dt1 =~ /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(Z|GMT|UTC)$/;
  $dt2 = substr($dt2, 0, 19) . "+0000" if $dt2 =~ /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(Z|GMT|UTC)$/;

  my $tp1 = Time::Piece->strptime($dt1, '%Y-%m-%dT%H:%M:%S%z');
  my $tp2 = Time::Piece->strptime($dt2, '%Y-%m-%dT%H:%M:%S%z');
  return -1 if $tp1 < $tp2;
  return  1 if $tp1 > $tp2;
  return 0;
}

1;
