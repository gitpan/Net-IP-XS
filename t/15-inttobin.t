#!perl

use warnings;
use strict;

use Test::More tests => 13;

use Net::IP::XS qw(ip_inttobin Error Errno);

my $res = ip_inttobin('1', 0);
is($res, undef, 'ip_inttobin invalid');
is(Error(), 'Cannot determine IP version for 1', 'Got correct error');
is(Errno(), 101, 'Got correct errno');

$res = ip_inttobin('1', 6);
is($res, ('0' x 127).'1', 'ip_inttobin 1');
$res = ip_inttobin('170', 6);
is($res, ('0' x 120).'10101010', 'ip_inttobin 2');
$res = ip_inttobin('1', 4);
is($res, ('0' x 31).'1', 'ip_inttobin 3');
$res = ip_inttobin('170', 4);
is($res, ('0' x 24).'10101010', 'ip_inttobin 4');
$res = ip_inttobin('1', 8);
is($res, 1, 'ip_inttobin 5');

use Math::BigInt;
$res = ip_inttobin(Math::BigInt->new("12324124312431243"), 4);
is($res, '101011110010001011100111001011110011110110101010001011', 
    'ip_inttobin bigint 1');

$res = ip_inttobin(Math::BigInt->new("4294967295"), 4);
is($res, '1' x 32, 'ip_inttobin bigint 2');

$res = ip_inttobin(
    Math::BigInt->new("340282366920938463463374607431768211455"), 
    4
);
is($res, '1' x 128, 'ip_inttobin bigint 3');
$res = ip_inttobin(
    Math::BigInt->new("340282366920938463463374607431768211456"), 
    4
);
is($res, undef, 'Got undef on a number that was too large');

$res = ip_inttobin('ABCD', 4);
is($res, ('0' x 32), 'Got zero address on non-integer');

1;
