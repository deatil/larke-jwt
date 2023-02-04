<?php

namespace Larke\JWT\Signer;

use Larke\JWT\Contracts\Key;
use Larke\JWT\Exception\InvalidKeyProvided;

use function strlen;
use function hash_equals;
use function sodium_crypto_generichash;

/**
 * Blake2b signers
 */
final class Blake2b extends BaseSigner
{
    private const MINIMUM_KEY_LENGTH_IN_BITS = 256;

    public function getAlgorithmId()
    {
        return 'BLAKE2B';
    }

    public function createHash($payload, Key $key)
    {
        $actualKeyLength = 8 * strlen($key->getContent());

        if ($actualKeyLength < self::MINIMUM_KEY_LENGTH_IN_BITS) {
            throw InvalidKeyProvided::tooShort(self::MINIMUM_KEY_LENGTH_IN_BITS, $actualKeyLength);
        }

        return sodium_crypto_generichash($payload, $key->getContent());
    }

    public function doVerify($expected, $payload, Key $key)
    {
        return hash_equals($expected, $this->createHash($payload, $key));
    }
}