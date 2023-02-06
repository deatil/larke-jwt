<?php

declare (strict_types = 1);

namespace Larke\JWT\Signer\Hmac;

use Larke\JWT\Signer\Hmac;

/**
 * Signer for HMAC SHA-256
 */
final class Sha256 extends Hmac
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId()
    {
        return 'HS256';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm()
    {
        return 'sha256';
    }
}
