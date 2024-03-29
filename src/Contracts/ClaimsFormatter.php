<?php

declare(strict_types=1);

namespace Larke\JWT\Contracts;

interface ClaimsFormatter
{
    /**
     * @param array<non-empty-string, mixed> $claims
     *
     * @return array<non-empty-string, mixed>
     */
    public function formatClaims(array $claims): array;
}
