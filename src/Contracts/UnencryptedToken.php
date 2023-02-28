<?php

declare (strict_types = 1);

namespace Larke\JWT\Contracts;

use Larke\JWT\DataSet;
use Larke\JWT\Signature;

interface UnencryptedToken extends Token
{
    /**
     * Returns the token claims
     */
    public function getClaims(): DataSet;

    /**
     * Returns the token signature
     */
    public function getSignature(): Signature;

    /**
     * Returns the token payload
     *
     * @return non-empty-string
     */
    public function getPayload(): string;
}
