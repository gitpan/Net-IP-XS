use strict;
use warnings;
use ExtUtils::MakeMaker;
use ExtUtils::MakeMaker::Config;

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

# Adapted from Math::GMP.

if (not exists $output->{'EXTRALIBS'} or $output->{'EXTRALIBS'} !~ /gmp/) {
    my $makefile_msg = 
        exists $output->{'MAKEFILE'}
            ? "\nRemoving ($output->{'MAKEFILE'})\n" 
            : '';

    warn qq(No GMP libraries detected!);
    if ($makefile_msg) {
        print $makefile_msg;
        unlink $output->{'MAKEFILE'};
    }

    exit 1;
}

1;
