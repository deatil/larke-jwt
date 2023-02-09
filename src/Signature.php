<?php

declare (strict_types = 1);

namespace Larke\JWT;

use Larke\JWT\Contracts\Key;
use Larke\JWT\Contracts\Signer;

/**
 * This class represents a token signature
 */
class Signature
{
    /**
     * The resultant hash
     *
     * @var string
     */
    protected $hash;

    /**
     * The resultant encoded
     *
     * @var string
     */
    protected $encoded;

    /**
     * Initializes the object
     *
     * @param string $hash
     */
    public function __construct(string $hash, string $encoded)
    {
        $this->hash    = $hash;
        $this->encoded = $encoded;
    }

    /** @return non-empty-string */
    public function hash(): string
    {
        return $this->hash;
    }

    /**
     * Verifies if the current hash matches with with the result of the creation of
     * a new signature with given data
     *
     * @param Signer $signer
     * @param string $payload
     * @param Key    $key
     *
     * @return boolean
     */
    public function verify(Signer $signer, string $payload, Key $key): bool
    {
        return $signer->verify($this->hash, $payload, $key);
    }

    /**
     * Returns the current encoded as a string representation of the signature
     *
     * @return string
     */
    public function toString(): string
    {
        return $this->encoded;
    }

    /**
     * Returns the current encoded as a string representation of the signature
     *
     * @return string
     */
    public function __toString(): string
    {
        return $this->toString();
    }
}
