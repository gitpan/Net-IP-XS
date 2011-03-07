use strict;
use warnings;

use lib qw(inc);
use Devel::CheckLib;
use ExtUtils::MakeMaker;
use ExtUtils::MakeMaker::Config;

check_lib_or_exit(lib => 'gmp', header => 'gmp.h');

my $output = WriteMakefile(
    NAME           => 'Net::IP::XS',
    AUTHOR         => 'Tom Harrison <tomhrr@cpan.org>',
    VERSION_FROM   => 'lib/Net/IP/XS.pm',
    ABSTRACT_FROM  => 'lib/Net/IP/XS.pm',
    LIBS           => ['-lgmp'],
    CCFLAGS        => '-Wall '.
                      '-Wno-unused-value '.
                      '-Wno-unused-variable',
    PERL_MALLOC_OK => 1,
    OBJECT         => '$(O_FILES)',
    clean          => { FILES => '$(O_FILES)' },
    PREREQ_PM      => { 'Tie::Hash::Sorted'   => 0,
                        'Tie::Simple'         => 0,
                        'Math::BigInt'        => 0,
                        'IP::Authority'       => 0,
                        # Test prereqs.
                        'Test::More'          => 0,
                        'IO::Capture::Stderr' => 0 },
);

1;
