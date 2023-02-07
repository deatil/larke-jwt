<?php

declare (strict_types = 1);

namespace Larke\JWT\Contracts;

use Larke\JWT\ValidationData;

/**
 * Basic interface for validatable token claims
 */
interface Validatable
{
    /**
     * Returns if claim is valid according with given data
     *
     * @param ValidationData $data
     *
     * @return boolean
     */
    public function validate(ValidationData $data);
}
