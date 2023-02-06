<?php

declare (strict_types = 1);

namespace Larke\JWT\Signer\Rsa;

use Larke\JWT\Signer\Rsa;

/**
 * Signer for RSA SHA-384
 */
final class Sha384 extends Rsa
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId()
    {
        return 'RS384';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm()
    {
        return OPENSSL_ALGO_SHA384;
    }
}
