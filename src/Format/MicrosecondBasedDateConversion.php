<?php

declare(strict_types=1);

namespace Larke\JWT\Format;

use DateTimeInterface;

use Larke\JWT\Claim\RegisteredClaims;
use Larke\JWT\Contracts\ClaimsFormatter;

use function array_key_exists;

final class MicrosecondBasedDateConversion implements ClaimsFormatter
{
    /** @inheritdoc */
    public function formatClaims(array $claims): array
    {
        foreach (RegisteredClaims::DATE_CLAIMS as $claim) {
            if (! array_key_exists($claim, $claims)) {
                continue;
            }

            $claims[$claim] = $this->convertDate($claims[$claim]->getValue());
        }

        return $claims;
    }

    private function convertDate(DateTimeInterface $date): int
    {
        if ($date->format('u') === '000000') {
            return (int) $date->format('U');
        }

        return (float) $date->format('U.u');
    }
}
