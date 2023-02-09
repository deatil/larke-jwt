<?php

declare (strict_types = 1);

namespace Larke\JWT\Signer\Hmac;

use Larke\JWT\Signer\Hmac;

/**
 * Signer for HMAC SHA-512
 */
final class Sha512 extends Hmac
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId(): string
    {
        return 'HS512';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm(): string
    {
        return 'sha512';
    }
}
