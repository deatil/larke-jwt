<?php

declare (strict_types = 1);

namespace Larke\JWT;

use Generator;

use Larke\JWT\Contracts\Key;
use Larke\JWT\Contracts\Signer;
use Larke\JWT\Contracts\Validatable;
use Larke\JWT\Contracts\ValidationData;
use Larke\JWT\Claim\RegisteredHeaders;
use Larke\JWT\Claim\Factory as ClaimFactory;

final class Validator
{
    private ClaimFactory $claimFactory;

    public function __construct(
        ?ClaimFactory $claimFactory = null,
    ) {
        $this->claimFactory = $claimFactory ?: new ClaimFactory();
    }

    public function verify(Token $token, Signer $signer, Key $key): bool
    {
        if ($token->headers()->get(RegisteredHeaders::ALGORITHM) !== $signer->getAlgorithmId()) {
            return false;
        }
        
        $hash    = $token->signature()->hash();
        $payload = $token->payload();

        return $signer->verify($hash, $payload, $key);
    }

    public function validate(Token $token, ValidationData $data): bool
    {
        foreach ($this->getValidatableClaims($token) as $claim) {
            if (! $claim->validate($data)) {
                return false;
            }
        }

        return true;
    }

    private function getValidatableClaims(Token $token): Generator
    {
        foreach ($token->claims()->all() as $name => $value) {
            $claim = $this->claimFactory->create($name, $value);
            
            if ($claim instanceof Validatable) {
                yield $claim;
            }
        }
    }
}
