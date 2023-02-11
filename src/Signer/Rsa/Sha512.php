<?php

declare (strict_types = 1);

namespace Larke\JWT\Signer\Rsa;

use Larke\JWT\Signer\Rsa;

/**
 * Signer for RSA SHA-512
 */
final class Sha512 extends Rsa
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId(): string
    {
        return 'RS512';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm(): mixed
    {
        return OPENSSL_ALGO_SHA512;
    }
}
