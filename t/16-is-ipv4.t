#!perl

use warnings;
use strict;

use Test::More tests => 26;

use Net::IP::XS qw(ip_is_ipv4 Error Errno);

my @data = (
    [ '127' => 1 ],
    [ '0'   => 1 ],
    [ '255.255.255.255' => 1 ],
    [ '1.2.3.4' => 1 ],
    [ '192.168.0.1' => 1 ],
    [ '1.1.1.256' => 0,
      107, 'Invalid quad in IP address 1.1.1.256 - 256' ],
    [ '123459125' => 0,
      107, 'Invalid quad in IP address 123459125 - 123459125' ],
    [ 'ABCD' => 0,
      107, 'Invalid chars in IP ABCD' ],
    [ '.123' => 0,
      103, 'Invalid IP .123 - starts with a dot' ],
    [ '123.' => 0,
      104, 'Invalid IP 123. - ends with a dot' ],
    [ '1.....2' => 0,
      105, 'Invalid IP address 1.....2' ],
    [ '123..123.123' => 0,
      106, 'Empty quad in IP address 123..123.123' ]
);

for my $entry (@data) {
    my ($input, $res, $errno, $error) = @{$entry};
    my $res_t = ip_is_ipv4($input);
    is($res_t, $res, "Got correct ip_is_ipv4 result for $input");
    if (defined $errno) {
        is(Errno(), $errno, 'Got correct errno');
    }
    if (defined $error) {
        is(Error(), $error, 'Got correct error');
    }
}

1;
