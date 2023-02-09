<?php

declare (strict_types = 1);

namespace Larke\JWT;

use Generator;
use DateTimeImmutable;
use DateTimeInterface;
use OutOfBoundsException;

use Larke\JWT\Contracts\Key;
use Larke\JWT\Contracts\Claim;
use Larke\JWT\Contracts\Signer;
use Larke\JWT\Contracts\Validatable;
use Larke\JWT\Claim\RegisteredClaims;
use Larke\JWT\Claim\RegisteredHeaders;

/**
 * Basic structure of the JWT
 */
class Token
{
    /**
     * The token headers
     *
     * @var DataSet
     */
    private $headers;

    /**
     * The token claim set
     *
     * @var DataSet
     */
    private $claims;

    /**
     * The token signature
     *
     * @var Signature
     */
    private $signature;

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
    public function getHeaders(): DataSet
    {
        return $this->headers;
    }

    /**
     * Returns if the header is configured
     *
     * @param string $name
     *
     * @return boolean
     */
    public function hasHeader(string $name): bool
    {
        return $this->headers->has($name);
    }

    /**
     * Returns the value of a token header
     *
     * @param string $name
     * @param mixed  $default
     *
     * @return mixed
     *
     * @throws OutOfBoundsException
     */
    public function getHeader(string $name, mixed $default = null): mixed
    {
        if ($this->hasHeader($name)) {
            return $this->getHeaderValue($name);
        }

        if ($default === null) {
            throw new OutOfBoundsException('Requested header is not configured');
        }

        return $default;
    }

    /**
     * Returns the value stored in header
     *
     * @param string $name
     *
     * @return mixed
     */
    private function getHeaderValue(string $name): mixed
    {
        $header = $this->headers->get($name);

        if ($header instanceof Claim) {
            return $header->getValue();
        }

        return $header;
    }

    /**
     * Returns the token claim set
     *
     * @return DataSet
     */
    public function getClaims(): DataSet
    {
        return $this->claims;
    }

    /**
     * Returns if the claim is configured
     *
     * @param string $name
     *
     * @return boolean
     */
    public function hasClaim(string $name): bool
    {
        return $this->claims->has($name);
    }

    /**
     * Returns the value of a token claim
     *
     * @param string $name
     * @param mixed  $default
     *
     * @return mixed
     *
     * @throws OutOfBoundsException
     */
    public function getClaim(string $name, mixed $default = null): mixed
    {
        if ($this->hasClaim($name)) {
            return $this->claims->get($name)->getValue();
        }

        if ($default === null) {
            throw new OutOfBoundsException('Requested claim is not configured');
        }

        return $default;
    }

    /**
     * Verify if the key matches with the one that created the signature
     *
     * @param Signer     $signer
     * @param Key|string $key
     *
     * @return boolean
     */
    public function verify(Signer $signer, $key): bool
    {
        if ($this->headers->get(RegisteredHeaders::ALGORITHM) !== $signer->getAlgorithmId()) {
            return false;
        }

        return $this->signature->verify($signer, $this->getPayload(), $key);
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

    /**
     * Determine if the token is expired.
     *
     * @param DateTimeInterface $now Defaults to the current time.
     *
     * @return bool
     */
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

    /**
     * Returns the token signature
     *
     * @return Signature
     */
    public function getSignature(): Signature
    {
        return $this->signature;
    }

    /**
     * Returns the token payload
     *
     * @return string
     */
    public function getPayload(): string
    {
        return $this->headers->toString() . '.' . $this->claims->toString();
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

    /**
     * Returns an encoded representation of the token
     *
     * @return string
     */
    public function __toString(): string
    {
        return $this->toString();
    }
}
