<?php

declare(strict_types=1);

namespace Larke\JWT\Clock;

use DateTimeZone;
use DateTimeImmutable;

use Larke\JWT\Contracts\Clock;

use function date_default_timezone_get;

final class FrozenClock implements Clock
{
    private $now;

    public function __construct(DateTimeImmutable $now)
    {
        $this->now = $now;
    }

    public static function fromUTC(): self
    {
        return new self(new DateTimeImmutable('now', new DateTimeZone('UTC')));
    }

    public static function fromSystemTimezone(): self
    {
        return new self(new DateTimeImmutable('now', new DateTimeZone(date_default_timezone_get())));
    }

    public function setTo(DateTimeImmutable $now)
    {
        $this->now = $now;
    }

    public function now(): DateTimeImmutable
    {
        return $this->now;
    }
}
