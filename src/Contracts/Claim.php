<?php

declare (strict_types = 1);

namespace Larke\JWT\Contracts;

use JsonSerializable;

/**
 * Basic interface for token claims
 */
interface Claim extends JsonSerializable
{
    /**
     * Returns the claim name
     *
     * @return string
     */
    public function getName(): string;

    /**
     * Returns the claim value
     *
     * @return mixed
     */
    public function getValue(): mixed;

    /**
     * Returns the string representation of the claim
     *
     * @return string
     */
    public function toString(): string;
}
