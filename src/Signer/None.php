<?php

declare (strict_types = 1);

namespace Larke\JWT\Signer;

use Larke\JWT\Contracts\Key;

/**
 * None signers
 */
final class None extends BaseSigner
{
    public function getAlgorithmId(): string
    {
        return 'none';
    }

    public function createHash(string $payload, Key $key): string
    {
        return "";
    }

    public function doVerify(string $expected, string $payload, Key $key): bool
    {
        return $expected === '';
    }
}