use strict;
use Test::More (tests => 2);
use Test::Requires 'Net::OpenID::Consumer';

use_ok("Crypt::DH::GMP");

my $dh = Crypt::DH::GMP->new(
    p => "0xdcf93a0b883972ec0e19989ac5a2ce310e1d37717e8d9571bb7623731866e61ef75a2e27898b057f9891c2e27a639c3f29b60814581cd3b2ca3986d2683705577d45c2e7e52dc81c7a171876e5cea74b1448bfdfaf18828efd2519f14e45e3826634af1949e5b535cc829a483b8a76223e5d490a257f05bdff16f2fb22f5615b",
    g => "2",
);
$dh->generate_keys;

my $pub_key_dec = $dh->pub_key;
my $pub_key_bi  = Math::BigInt->new($pub_key_dec);

is( pack("B*", $dh->pub_key_twoc), OpenID::util::bi2bytes($pub_key_bi), "pub_key_twoc produces the same results as OpenID::util::bi2bytes" );

