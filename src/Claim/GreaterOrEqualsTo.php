<?php

declare (strict_types = 1);

namespace Larke\JWT\Claim;

use Larke\JWT\Contracts\Claim;
use Larke\JWT\Contracts\Validatable;
use Larke\JWT\ValidationData;

/**
 * Validatable claim that checks if value is greater or equals the given data
 */
class GreaterOrEqualsTo extends Basic implements Claim, Validatable
{
    /**
     * {@inheritdoc}
     */
    public function validate(ValidationData $data): bool
    {
        if ($data->has($this->getName())) {
            return $this->getValue() >= $data->get($this->getName());
        }

        return true;
    }
}
