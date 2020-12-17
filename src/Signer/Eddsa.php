<?php

namespace Larke\JWT\Signer;

use SodiumException;

use Larke\JWT\Exception\InvalidKeyProvided;
use Larke\JWT\Contracts\Signer;
use Larke\JWT\Contracts\Key;

use function sodium_crypto_sign_detached;
use function sodium_crypto_sign_verify_detached;

/**
 * EDDSA signers
 */
final class Eddsa implements Signer
{
    public function algorithmId()
    {
        return 'EdDSA';
    }

    public function sign(string $payload, Key $key)
    {
        try {
            return sodium_crypto_sign_detached($payload, $key->contents());
        } catch (SodiumException $sodiumException) {
            throw new InvalidKeyProvided($sodiumException->getMessage(), 0, $sodiumException);
        }
    }

    public function verify(string $expected, string $payload, Key $key)
    {
        try {
            return sodium_crypto_sign_verify_detached($expected, $payload, $key->contents());
        } catch (SodiumException $sodiumException) {
            throw new InvalidKeyProvided($sodiumException->getMessage(), 0, $sodiumException);
        }
    }
}