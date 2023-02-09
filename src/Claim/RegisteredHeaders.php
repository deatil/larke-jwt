<?php

declare (strict_types = 1);

namespace Larke\JWT\Claim;

/**
 * Defines the list of headers that are registered in the IANA "JSON Web Token Headers" registry
 */
final class RegisteredHeaders
{
    /**
     * Type
     */
    public const TYPE = 'typ';

    /**
     * Algorithm
     */
    public const ALGORITHM = 'alg';

    /**
     * Encryption
     */
    public const ENCRYPTION = 'enc';
}
