<?php

declare (strict_types = 1);

namespace Larke\JWT\Signer\Hmac;

use Larke\JWT\Signer\Hmac;

/**
 * Signer for HMAC SHA-384
 */
final class Sha384 extends Hmac
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId()
    {
        return 'HS384';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm()
    {
        return 'sha384';
    }
}
