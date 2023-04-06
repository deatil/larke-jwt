<?php

declare (strict_types = 1);

namespace Larke\JWT;

use DateTimeImmutable;

use Larke\JWT\Contracts\Key;
use Larke\JWT\Contracts\Signer;
use Larke\JWT\Contracts\Encoder;
use Larke\JWT\Contracts\ClaimsFormatter;
use Larke\JWT\Contracts\UnencryptedToken;
use Larke\JWT\Encoding\JoseEncoder;
use Larke\JWT\Claim\RegisteredClaims;
use Larke\JWT\Claim\RegisteredHeaders;
use Larke\JWT\Format\ChainedFormatter;
use Larke\JWT\Exception\RegisteredClaimGiven;

/**
 * This class makes easier the token creation process
 */
final class Builder
{
    /**
     * The token header
     *
     * @var array
     */
    private array $headers = [
        RegisteredHeaders::TYPE      => 'JWT', 
        RegisteredHeaders::ALGORITHM => 'none'
    ];

    /**
     * The token claim set
     *
     * @var array
     */
    private array $claims = [];

    /**
     * The data encoder
     *
     * @var Encoder
     */
    private Encoder $encoder;

    /**
     * The formatter of claims
     *
     * @var ClaimsFormatter
     */
    private ClaimsFormatter $claimFormatter;

    /**
     * Initializes a new builder
     *
     * @param Encoder         $encoder
     * @param ClaimsFormatter $claimFormatter
     */
    public function __construct(
        ?Encoder         $encoder = null,
        ?ClaimsFormatter $claimFormatter = null
    ) {
        $this->encoder        = $encoder ?: new JoseEncoder();
        $this->claimFormatter = $claimFormatter ?: ChainedFormatter::withUnixTimestampDates();
    }

    /**
     * Configures the audience
     *
     * @param string $audiences
     *
     * @return Builder
     */
    public function permittedFor(string ...$audiences): self
    {
        $configured = $this->claims[RegisteredClaims::AUDIENCE] ?? [];
        $toAppend   = array_diff($audiences, $configured);

        return $this->setClaim(RegisteredClaims::AUDIENCE, array_merge($configured, $toAppend));
    }

    /**
     * Configures the expiration time, expirTime
     *
     * @param DateTimeImmutable $expiration
     *
     * @return Builder
     */
    public function expiresAt(DateTimeImmutable $expiration): self
    {
        return $this->setClaim(RegisteredClaims::EXPIRATION_TIME, $expiration);
    }

    /**
     * Configures the token id JwtId
     *
     * @param string $id
     *
     * @return Builder
     */
    public function identifiedBy(string $id): self
    {
        return $this->setClaim(RegisteredClaims::ID, $id);
    }

    /**
     * Configures the time that the token was issued
     *
     * @param DateTimeImmutable $issuedAt
     *
     * @return Builder
     */
    public function issuedAt(DateTimeImmutable $issuedAt): self
    {
        return $this->setClaim(RegisteredClaims::ISSUED_AT, $issuedAt);
    }

    /**
     * Configures the issuer
     *
     * @param string $issuer
     *
     * @return Builder
     */
    public function issuedBy(string $issuer): self
    {
        return $this->setClaim(RegisteredClaims::ISSUER, $issuer);
    }

    /**
     * Configures the time before which the token cannot be accepted
     *
     * @param DateTimeImmutable $notBefore
     *
     * @return Builder
     */
    public function canOnlyBeUsedAfter(DateTimeImmutable $notBefore): self
    {
        return $this->setClaim(RegisteredClaims::NOT_BEFORE, $notBefore);
    }

    /**
     * Configures the subject
     *
     * @param string  $subject
     *
     * @return Builder
     */
    public function relatedTo(string $subject): self
    {
        return $this->setClaim(RegisteredClaims::SUBJECT, $subject);
    }

    /**
     * Configures a header item
     *
     * @param string $name
     * @param mixed  $value
     *
     * @return Builder
     */
    public function withHeader(string $name, mixed $value): self
    {
        $this->headers[$name] = $value;

        return $this;
    }

    /**
     * Configures a claim item
     *
     * @param string $name
     * @param mixed  $value
     *
     * @return Builder
     */
    public function withClaim(string $name, mixed $value): self
    {
        if (in_array($name, RegisteredClaims::ALL, true)) {
            throw RegisteredClaimGiven::forClaim($name);
        }

        return $this->setClaim($name, $value);
    }

    /** @param non-empty-string $name */
    private function setClaim(string $name, mixed $value): self
    {
        $this->claims[$name] = $value;

        return $this;
    }
    
    /**
     * Returns the encoded data
     *
     * @param array $data
     *
     * @return string
     */
    private function encode(array $data): string
    {
        return $this->encoder->base64UrlEncode(
            $this->encoder->jsonEncode($data)
        );
    }

    /**
     * Returns the resultant token
     *
     * @return UnencryptedToken
     */
    public function getToken(Signer $signer, Key $key): UnencryptedToken
    {
        $signer->modifyHeader($this->headers);
        
        $encodedHeaders = $this->encode($this->headers);
        $encodedClaims  = $this->encode($this->claimFormatter->formatClaims($this->claims));
        
        $signature        = $signer->sign($encodedHeaders . '.' . $encodedClaims, $key);
        $encodedSignature = $this->encoder->base64UrlEncode($signature);

        return new Token(
            new DataSet($this->headers, $encodedHeaders),
            new DataSet($this->claims, $encodedClaims),
            new Signature($signature, $encodedSignature)
        );
    }
}
