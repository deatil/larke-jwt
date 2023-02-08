<?php

declare(strict_types=1);

namespace Larke\JWT\Contracts;

use DateTimeImmutable;

interface Clock
{
    public function now(): DateTimeImmutable;
}
