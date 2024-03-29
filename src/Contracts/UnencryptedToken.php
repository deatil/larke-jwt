<?php

declare (strict_types = 1);

namespace Larke\JWT\Contracts;

interface UnencryptedToken extends Token
{
    /**
     * Returns the token claims
     */
    public function claims(): DataSet;

    /**
     * Returns the token signature
     */
    public function signature(): Signature;

    /**
     * Returns the token payload
     *
     * @return non-empty-string
     */
    public function payload(): string;
}
