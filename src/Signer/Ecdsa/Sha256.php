<?php

declare (strict_types = 1);

namespace Larke\JWT\Signer\Ecdsa;

use Larke\JWT\Signer\Ecdsa;

/**
 * Signer for ECDSA SHA-256
 */
final class Sha256 extends Ecdsa
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId()
    {
        return 'ES256';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm()
    {
        return 'sha256';
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength()
    {
        return 64;
    }
}
