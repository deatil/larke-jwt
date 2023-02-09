<?php

declare (strict_types = 1);

namespace Larke\JWT\Signer;

use Larke\JWT\Contracts\Signer;
use Larke\JWT\Contracts\Key;
use Larke\JWT\Signer\Key\InMemory;
use Larke\JWT\Claim\RegisteredHeaders;

use function is_string;

/**
 * Base class for signers
 */
abstract class BaseSigner implements Signer
{
    /**
     * {@inheritdoc}
     */
    public function modifyHeader(array &$headers)
    {
        $headers[RegisteredHeaders::ALGORITHM] = $this->getAlgorithmId();
    }

    /**
     * {@inheritdoc}
     */
    public function sign(string $payload, Key $key): string
    {
        return $this->createHash($payload, $key);
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $expected, string $payload, Key $key): bool
    {
        return $this->doVerify($expected, $payload, $key);
    }

    /**
     * Creates a hash with the given data
     *
     * @internal
     *
     * @param string $payload
     * @param Key    $key
     *
     * @return string
     */
    abstract public function createHash(string $payload, Key $key): string;

    /**
     * Performs the signature verification
     *
     * @internal
     *
     * @param string $expected
     * @param string $payload
     * @param Key    $key
     *
     * @return boolean
     */
    abstract public function doVerify(string $expected, string $payload, Key $key): bool;
}
