<?php

declare (strict_types = 1);

namespace Larke\JWT\Signer\Ecdsa;

use Larke\JWT\Signer\Ecdsa;

/**
 * Signer for ECDSA SHA-384
 */
final class Sha384 extends Ecdsa
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId(): string
    {
        return 'ES384';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm(): string
    {
        return 'sha384';
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return 96;
    }
}
