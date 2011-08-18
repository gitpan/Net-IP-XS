#!perl

use warnings;
use strict;

use Test::More tests => 45;

use Net::IP::XS qw(ip_expand_address);
use IO::Capture::Stderr;
my $c = IO::Capture::Stderr->new();

$c->start();
is(ip_expand_address(undef, 4), '0.0.0.0',
    'Got zero address on undef (IPv4)');
is(ip_expand_address(undef, 6), (join ':', ('0000') x 8),
    'Got zero address on undef (IPv6)');
$c->stop();
is(ip_expand_address('', 4), '0.0.0.0',
    'Got zero address on empty string (IPv4)');
is(ip_expand_address('', 6), (join ':', ('0000') x 8),
    'Got zero address on string (IPv6)');

is(ip_expand_address('ZXCV', 4), undef,
    'Got undef on invalid IPv4 address');
is(ip_expand_address('ZXCV', 6), undef,
    'Got undef on invalid IPv4 address');

my @data = (
    ['0' => '0.0.0.0'],
    ['0.0' => '0.0.0.0'],
    ['0.0.0' => '0.0.0.0'],
    ['0.0.0.0' => '0.0.0.0'],
    ['0.1.2.3' => '0.1.2.3'],
    ['255.255.255.255' => '255.255.255.255'],
    ['1' => '1.0.0.0'],
    ['1.2' => '1.2.0.0'],
    ['1.2.3' => '1.2.3.0'],
    ['1.2.3.4.5' => undef],
);

for (@data) {
    my ($key, $value) = @{$_};
    is(ip_expand_address($key, 4), $value,
        "v4: $key");
}

@data = (
    ['::'              => '0000:0000:0000:0000:0000:0000:0000:0000'],
    ['::1234'          => '0000:0000:0000:0000:0000:0000:0000:1234'],
    ['1234::'          => '1234:0000:0000:0000:0000:0000:0000:0000'],
    ['1234:5678::'     => '1234:5678:0000:0000:0000:0000:0000:0000'],
    ['1234::5678'      => '1234:0000:0000:0000:0000:0000:0000:5678'],
    ['0::0'            => '0000:0000:0000:0000:0000:0000:0000:0000'],
    ['0:0:0:0:0:0:0:0' => '0000:0000:0000:0000:0000:0000:0000:0000'],
    ['0000:0000:0000:0000:0000:0000:0000:0000' =>
     '0000:0000:0000:0000:0000:0000:0000:0000'],
    ['1234:5678::ABCD:EF12' =>
    '1234:5678:0000:0000:0000:0000:abcd:ef12'],
    ['1234:5678::ABCD:EF12:3456:7890' =>
    '1234:5678:0000:0000:abcd:ef12:3456:7890'],
    ['1234:5678:ABCD::ABCD:EF12:3456:7890' =>
    '1234:5678:abcd:0000:abcd:ef12:3456:7890'],
    ['1.2.3.4::' => '0102:0304:0000:0000:0000:0000:0000:0000'],
    ['1.2.3.4:255.255.255.255::' 
    => '0102:0304:ffff:ffff:0000:0000:0000:0000'],
    ['255.255.255.255:255.255.255.255::' 
    => 'ffff:ffff:ffff:ffff:0000:0000:0000:0000'],
    ['255.255.255.255:255.255.255.255:255.255.255.255:255.255.255.255'
    => 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
    ['255.255.255.255:255.255.255.255:255.255.255.255:'.
     '255.255.255.255:255.255.255.255' => undef],
    ['1.2.3.4:100.100.100.100::'
    => '0102:0304:6464:6464:0000:0000:0000:0000' ],
    ['A:B:C:D::'
    => '000a:000b:000c:000d:0000:0000:0000:0000'],
    ['ff00::1234',
    => 'ff00:0000:0000:0000:0000:0000:0000:1234'],
    ['0', '0000:0000:0000:0000:0000:0000:0000:0000'],
    [':FFFF' => undef],
    ['FFFFF' => undef],
    ['FFFF:' => undef],
    ['FFFF:::' => undef],
    ['0000:0000:0000:0000:0000:0000:0000:0000::' => undef],
    ['0000:0000:0000:0000:123.123.123.123.123.123:0000:0000' => undef],
    ['1:2:3:4:1:2:3:4:1:2:3:4' => undef],
    ['1:2:3:4:1:2:3:4:1' => undef],
    ['1111:2222:3333:4444:1111:2222:3333:4444:1111:2222:3333:4444' => undef],
);

for my $entry (@data) {
    my ($key, $value) = @{$entry};
    is(ip_expand_address($key, 6), $value,
        "v6: $key");
}

1;
