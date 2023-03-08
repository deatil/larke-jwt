<?php

declare (strict_types = 1);

namespace Larke\JWT;

use Larke\JWT\Contracts\Signature as BaseSignature;

/**
 * This class represents a token signature
 */
final class Signature implements BaseSignature
{
    /**
     * The resultant hash
     *
     * @var string
     */
    protected string $hash;

    /**
     * The resultant encoded
     *
     * @var string
     */
    protected string $encoded;

    /**
     * Initializes the object
     *
     * @param string $hash
     * @param string $encoded
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
     * Returns the current encoded as a string representation of the signature
     *
     * @return string
     */
    public function toString(): string
    {
        return $this->encoded;
    }
}
