<?php

declare (strict_types = 1);

namespace Larke\JWT\Claim;

use Larke\JWT\Contracts\Claim;

/**
 * The default claim
 */
class Basic implements Claim
{
    /**
     * @var string
     */
    private string $name;

    /**
     * @var mixed
     */
    private mixed $value;

    /**
     * Initializes the claim
     *
     * @param string $name
     * @param mixed $value
     */
    public function __construct(string $name, mixed $value)
    {
        $this->name  = $name;
        $this->value = $value;
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * {@inheritdoc}
     */
    public function getValue(): mixed
    {
        return $this->value;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize(): mixed
    {
        return $this->value;
    }

    /**
     * {@inheritdoc}
     */
    public function toString(): string
    {
        return (string) $this->value;
    }
}
