<?php

declare (strict_types = 1);

namespace Larke\JWT\Signer\Ecdsa;

use Larke\JWT\Signer\Ecdsa;

/**
 * Signer for ECDSA SHA-512
 */
final class Sha512 extends Ecdsa
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId(): string
    {
        return 'ES512';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm(): mixed
    {
        return 'sha512';
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return 132;
    }
}
