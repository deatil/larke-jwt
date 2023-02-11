<?php

declare (strict_types = 1);

namespace Larke\JWT\Signer\Rsa;

use Larke\JWT\Signer\Rsa;

/**
 * Signer for RSA SHA-256
 */
final class Sha256 extends Rsa
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId(): string
    {
        return 'RS256';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm(): mixed
    {
        return OPENSSL_ALGO_SHA256;
    }
}
