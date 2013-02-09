use 5.010;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Mojo::MITM',
    AUTHOR           => 'Karel Miko',
    VERSION_FROM     => 'lib/Mojo/MITM.pm',
    ABSTRACT         => 'Non-blocking Man-In-The-Middle (MITM) HTTP proxy',
    EXE_FILES        => [ 'script/mojo-mitm' ],
    MIN_PERL_VERSION => 5.010,
    PREREQ_PM        => {
      'Net::SSLeay'      => 1.50,
      'IO::Socket::SSL'  => 1.75,
      'IO::Socket::IP'   => 0.16,
      'Mojolicious'      => 3.30,
      'Getopt::Long'     => 2.13,
      'Test::More'       => 0,
      'Time::Piece'      => 0,
      'Time::HiRes'      => 0,
      'Term::ReadKey'    => 0,
      'File::Spec'       => 0,
      'File::Slurp'      => 0,
      'File::HomeDir'    => 0,
      'Data::Dump'       => 0,
    },
);
