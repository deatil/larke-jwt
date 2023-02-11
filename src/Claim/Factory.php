<?php

declare (strict_types = 1);

namespace Larke\JWT\Claim;

use Larke\JWT\Contracts\Claim;

use function array_merge;
use function call_user_func;

/**
 * Class that create claims
 */
class Factory
{
    /**
     * The list of claim callbacks
     *
     * @var array
     */
    private array $callbacks = [];

    /**
     * Initializes the factory, registering the default callbacks
     *
     * @param array $callbacks
     */
    public function __construct(array $callbacks = [])
    {
        $this->callbacks = array_merge(
            [
                RegisteredClaims::ISSUED_AT       => [$this, 'createLesserOrEqualsTo'],
                RegisteredClaims::NOT_BEFORE      => [$this, 'createLesserOrEqualsTo'],
                RegisteredClaims::EXPIRATION_TIME => [$this, 'createGreaterOrEqualsTo'],
                RegisteredClaims::ISSUER          => [$this, 'createEqualsTo'],
                RegisteredClaims::AUDIENCE        => [$this, 'createEqualsTo'],
                RegisteredClaims::SUBJECT         => [$this, 'createEqualsTo'],
                RegisteredClaims::ID              => [$this, 'createEqualsTo']
            ],
            $callbacks
        );
    }

    /**
     * Create a new claim
     *
     * @param string $name
     * @param mixed  $value
     *
     * @return Claim
     */
    public function create(string $name, mixed $value): Claim
    {
        if (! empty($this->callbacks[$name])) {
            return call_user_func($this->callbacks[$name], $name, $value);
        }

        return $this->createBasic($name, $value);
    }

    /**
     * Creates a claim that can be compared (greator or equals)
     *
     * @param string $name
     * @param mixed  $value
     *
     * @return GreaterOrEqualsTo
     */
    private function createGreaterOrEqualsTo(string $name, mixed $value): GreaterOrEqualsTo
    {
        return new GreaterOrEqualsTo($name, $value);
    }

    /**
     * Creates a claim that can be compared (greator or equals)
     *
     * @param string $name
     * @param mixed  $value
     *
     * @return LesserOrEqualsTo
     */
    private function createLesserOrEqualsTo(string $name, mixed $value): LesserOrEqualsTo
    {
        return new LesserOrEqualsTo($name, $value);
    }

    /**
     * Creates a claim that can be compared (equals)
     *
     * @param string $name
     * @param mixed  $value
     *
     * @return EqualsTo
     */
    private function createEqualsTo(string $name, mixed $value): EqualsTo
    {
        return new EqualsTo($name, $value);
    }

    /**
     * Creates a basic claim
     *
     * @param string $name
     * @param mixed  $value
     *
     * @return Basic
     */
    private function createBasic(string $name, mixed $value): Basic
    {
        return new Basic($name, $value);
    }
}
