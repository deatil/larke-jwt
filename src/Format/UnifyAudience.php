<?php

declare(strict_types=1);

namespace Larke\JWT\Format;

use Larke\JWT\Claim\RegisteredClaims;
use Larke\JWT\Contracts\ClaimsFormatter;

use function count;
use function current;
use function array_key_exists;

final class UnifyAudience implements ClaimsFormatter
{
    /** @inheritdoc */
    public function formatClaims(array $claims): array
    {
        if (
            ! array_key_exists(RegisteredClaims::AUDIENCE, $claims)
            || count($claims[RegisteredClaims::AUDIENCE]) !== 1
        ) {
            return $claims;
        }

        $claims[RegisteredClaims::AUDIENCE] = current($claims[RegisteredClaims::AUDIENCE]);

        return $claims;
    }
}
