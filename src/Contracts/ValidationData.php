<?php

declare (strict_types = 1);

namespace Larke\JWT\Contracts;

interface ValidationData
{
    /**
     * Returns the requested item
     *
     * @param string $name
     *
     * @return mixed
     */
    public function get(string $name): mixed;

    /**
     * Returns if the item is present
     *
     * @param string $name
     *
     * @return boolean
     */
    public function has(string $name): bool;
}
