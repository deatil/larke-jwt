<?php

declare (strict_types = 1);

namespace Larke\JWT\Contracts;

/**
 * This class represents a token signature
 */
interface Signature
{
    /** @return non-empty-string */
    public function hash(): string;

    /**
     * Returns the current encoded as a string representation of the signature
     *
     * @return string
     */
    public function toString(): string;
}
