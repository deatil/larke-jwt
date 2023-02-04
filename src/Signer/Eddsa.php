<?php

namespace Larke\JWT\Signer;

use SodiumException;

use Larke\JWT\Contracts\Key;
use Larke\JWT\Exception\InvalidKeyProvided;

use function sodium_crypto_sign_detached;
use function sodium_crypto_sign_verify_detached;

/**
 * EDDSA signers
 */
final class Eddsa extends BaseSigner
{
    private const SIGN_SECRETKEYBYTES_KEY_LENGTH = SODIUM_CRYPTO_SIGN_SECRETKEYBYTES;
    
    public function getAlgorithmId()
    {
        return 'EdDSA';
    }
    
    public function createHash($payload, Key $key)
    {
        try {
            return sodium_crypto_sign_detached($payload, $key->getContent());
        } catch (SodiumException $sodiumException) {
            throw new InvalidKeyProvided("EdDSA Create error: " . $sodiumException->getMessage(), 0, $sodiumException);
        }
    }

    public function doVerify($expected, $payload, Key $key)
    {
        try {
            return sodium_crypto_sign_verify_detached($expected, $payload, $key->getContent());
        } catch (SodiumException $sodiumException) {
            throw new InvalidKeyProvided("EdDSA Verify error: " . $sodiumException->getMessage(), 0, $sodiumException);
        }
    }
}