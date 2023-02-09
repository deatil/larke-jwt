<?php

declare (strict_types = 1);

namespace Larke\JWT\Contracts;

use InvalidArgumentException;

/**
 * Basic interface for token signers
 */
interface Signer
{
    /**
     * Returns the algorithm id
     *
     * @return string
     */
    public function getAlgorithmId(): string;

    /**
     * Apply changes on headers according with algorithm
     *
     * @param array $headers
     */
    public function modifyHeader(array &$headers);

    /**
     * Returns a signature for given data
     *
     * @param string $payload
     * @param Key|string $key
     *
     * @return string
     *
     * @throws InvalidArgumentException When given key is invalid
     */
    public function sign(string $payload, mixed $key): string;

    /**
     * Returns if the expected hash matches with the data and key
     *
     * @param string $expected
     * @param string $payload
     * @param Key|string $key
     *
     * @return boolean
     *
     * @throws InvalidArgumentException When given key is invalid
     */
    public function verify(string $expected, string $payload, mixed $key): bool;
}
