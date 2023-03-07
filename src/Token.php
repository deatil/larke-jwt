<?php

declare (strict_types = 1);

namespace Larke\JWT;

use Generator;
use DateTimeImmutable;
use DateTimeInterface;

use Larke\JWT\Contracts\Key;
use Larke\JWT\Contracts\Claim;
use Larke\JWT\Contracts\Signer;
use Larke\JWT\Contracts\Validatable;
use Larke\JWT\Contracts\UnencryptedToken;
use Larke\JWT\Claim\RegisteredClaims;
use Larke\JWT\Claim\RegisteredHeaders;

/**
 * Basic structure of the JWT
 */
class Token implements UnencryptedToken
{
    /**
     * The token headers
     *
     * @var DataSet
     */
    private DataSet $headers;

    /**
     * The token claim set
     *
     * @var DataSet
     */
    private DataSet $claims;

    /**
     * The token signature
     *
     * @var Signature
     */
    private Signature $signature;

    /**
     * Initializes the object
     *
     * @param DataSet   $headers
     * @param DataSet   $claims
     * @param Signature $signature
     */
    public function __construct(
        DataSet   $headers,
        DataSet   $claims,
        Signature $signature
    ) {
        $this->headers   = $headers;
        $this->claims    = $claims;
        $this->signature = $signature;
    }

    /**
     * Returns the token headers
     *
     * @return DataSet
     */
    public function headers(): DataSet
    {
        return $this->headers;
    }

    /**
     * Returns the token claim set
     *
     * @return DataSet
     */
    public function claims(): DataSet
    {
        return $this->claims;
    }

    /**
     * Returns the token signature
     *
     * @return Signature
     */
    public function signature(): Signature
    {
        return $this->signature;
    }

    /**
     * Returns the token payload
     *
     * @return string
     */
    public function payload(): string
    {
        return $this->headers->toString() . '.' . $this->claims->toString();
    }

    /**
     * Verify if the key matches with the one that created the signature
     *
     * @param Signer $signer
     * @param Key    $key
     *
     * @return boolean
     */
    public function verify(Signer $signer, Key $key): bool
    {
        if ($this->headers->get(RegisteredHeaders::ALGORITHM) !== $signer->getAlgorithmId()) {
            return false;
        }

        return $this->signature->verify($signer, $this->payload(), $key);
    }

    /**
     * Validates if the token is valid
     *
     * @param ValidationData $data
     *
     * @return boolean
     */
    public function validate(ValidationData $data): bool
    {
        foreach ($this->getValidatableClaims() as $claim) {
            if (! $claim->validate($data)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Yields the validatable claims
     *
     * @return Generator
     */
    private function getValidatableClaims(): Generator
    {
        foreach ($this->claims->all() as $claim) {
            if ($claim instanceof Validatable) {
                yield $claim;
            }
        }
    }

    public function isPermittedFor(string $audience): bool
    {
        return $this->getClaim(RegisteredClaims::AUDIENCE) === $audience;
    }
    
    public function isIdentifiedBy(string $id): bool
    {
        return $this->getClaim(RegisteredClaims::ID) === $id;
    }

    public function isRelatedTo(string $subject): bool
    {
        return $this->getClaim(RegisteredClaims::SUBJECT) === $subject;
    }

    public function hasBeenIssuedBy(string ...$issuers): bool
    {
        return in_array($this->getClaim(RegisteredClaims::ISSUER), $issuers, true);
    }

    public function hasBeenIssuedBefore(DateTimeInterface $now): bool
    {
        return $now >= $this->getClaim(RegisteredClaims::ISSUED_AT);
    }

    public function isMinimumTimeBefore(DateTimeInterface $now): bool
    {
        return $now >= $this->getClaim(RegisteredClaims::NOT_BEFORE);
    }

    public function isExpired(DateTimeInterface $now = null): bool
    {
        $exp = $this->getClaim(RegisteredClaims::EXPIRATION_TIME, false);

        if ($exp === false) {
            return false;
        }

        $now = $now ?: new DateTimeImmutable();

        return $now > $exp;
    }

    /**
     * Returns an encoded representation of the token
     *
     * @return string
     */
    public function toString(): string
    {
        return $this->headers->toString() . '.'
             . $this->claims->toString() . '.'
             . $this->signature->toString();
    }
}
