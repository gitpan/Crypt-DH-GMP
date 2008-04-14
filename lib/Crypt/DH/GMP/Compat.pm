# $Id: /mirror/coderepos/lang/perl/Crypt-DH-GMP/trunk/lib/Crypt/DH/GMP/Compat.pm 50337 2008-04-14T14:57:52.111907Z daisuke  $

package Crypt::DH::GMP::Compat;

package # hide from PAUSE
    Crypt::DH;
use strict;
use warnings;
no warnings 'redefine';
use vars qw(@ISA);

# Add Crypt::DH::GMP as Crypt::DH's parent, and redefine all methods
BEGIN
{
    unshift @ISA, 'Crypt::DH::GMP';

    *Crypt::DH::new = sub { shift->SUPER::new(@_) };
    *Crypt::DH::g = sub { Math::BigInt->new(shift->SUPER::g(@_)) };
    *Crypt::DH::p = sub { Math::BigInt->new(shift->SUPER::p(@_)) };
    *Crypt::DH::pub_key = sub { Math::BigInt->new(shift->SUPER::pub_key(@_)) };
    *Crypt::DH::priv_key = sub { Math::BigInt->new(shift->SUPER::priv_key(@_)) };
    *Crypt::DH::generate_keys = sub { shift->SUPER::generate_keys(@_) };
    *Crypt::DH::compute_key = sub { shift->SUPER::compute_key(@_) };
    *Crypt::DH::compute_secret = \&Crypt::DH::compute_key;
}

1;

__END__

=head1 NAME

Crypt::DH::GMP::Compat - Compatibility Mode For Crypt::DH

=head1 SYNOPSIS

  use Crypt::DH;
  use Crypt::DH::GMP qw(-compat);

=head1 DESCRIPTION

Crypt::DH::GMP::Compat is a very invasive module that rewrites Crypt::DH's
@ISA and method names so that it uses Crypt::DH::GMP

=cut
