<?php

declare (strict_types = 1);

namespace Larke\JWT;

use DateTimeImmutable;

use Larke\JWT\Contracts\Key;
use Larke\JWT\Contracts\Signer;
use Larke\JWT\Contracts\Encoder;
use Larke\JWT\Contracts\ClaimsFormatter;
use Larke\JWT\Encoding\JoseEncoder;
use Larke\JWT\Claim\Factory as ClaimFactory;
use Larke\JWT\Claim\RegisteredClaims;
use Larke\JWT\Claim\RegisteredHeaders;
use Larke\JWT\Format\ChainedFormatter;

use function implode;

/**
 * This class makes easier the token creation process
 */
class Builder
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
     * The factory of claims
     *
     * @var ClaimFactory
     */
    private ClaimFactory $claimFactory;

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
     * @param ClaimFactory    $claimFactory
     * @param ClaimsFormatter $claimFormatter
     */
    public function __construct(
        Encoder         $encoder = null,
        ClaimFactory    $claimFactory = null,
        ClaimsFormatter $claimFormatter = null
    ) {
        $this->encoder        = $encoder ?: new JoseEncoder();
        $this->claimFactory   = $claimFactory ?: new ClaimFactory();
        $this->claimFormatter = $claimFormatter ?: ChainedFormatter::withUnixTimestampDates();
    }

    /**
     * Configures the audience
     *
     * @param string $audience
     * @param bool   $replicateAsHeader
     *
     * @return Builder
     */
    public function permittedFor(string $audience, bool $replicateAsHeader = false): self
    {
        return $this->withRegisteredClaim(RegisteredClaims::AUDIENCE, $audience, $replicateAsHeader);
    }

    /**
     * Configures the expiration time, expirTime
     *
     * @param DateTimeImmutable $expiration
     * @param boolean           $replicateAsHeader
     *
     * @return Builder
     */
    public function expiresAt(DateTimeImmutable $expiration, bool $replicateAsHeader = false): self
    {
        return $this->withRegisteredClaim(RegisteredClaims::EXPIRATION_TIME, $expiration, $replicateAsHeader);
    }

    /**
     * Configures the token id JwtId
     *
     * @param string  $id
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function identifiedBy(string $id, bool $replicateAsHeader = false): self
    {
        return $this->withRegisteredClaim(RegisteredClaims::ID, $id, $replicateAsHeader);
    }

    /**
     * Configures the time that the token was issued
     *
     * @param DateTimeImmutable $issuedAt
     * @param boolean           $replicateAsHeader
     *
     * @return Builder
     */
    public function issuedAt(DateTimeImmutable $issuedAt, bool $replicateAsHeader = false): self
    {
        return $this->withRegisteredClaim(RegisteredClaims::ISSUED_AT, $issuedAt, $replicateAsHeader);
    }

    /**
     * Configures the issuer
     *
     * @param string  $issuer
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function issuedBy(string $issuer, bool $replicateAsHeader = false): self
    {
        return $this->withRegisteredClaim(RegisteredClaims::ISSUER, $issuer, $replicateAsHeader);
    }

    /**
     * Configures the time before which the token cannot be accepted
     *
     * @param DateTimeImmutable $notBefore
     * @param boolean           $replicateAsHeader
     *
     * @return Builder
     */
    public function canOnlyBeUsedAfter(DateTimeImmutable $notBefore, bool $replicateAsHeader = false): self
    {
        return $this->withRegisteredClaim(RegisteredClaims::NOT_BEFORE, $notBefore, $replicateAsHeader);
    }

    /**
     * Configures the subject
     *
     * @param string  $subject
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function relatedTo(string $subject, bool $replicateAsHeader = false): self
    {
        return $this->withRegisteredClaim(RegisteredClaims::SUBJECT, $subject, $replicateAsHeader);
    }

    /**
     * Configures a registered claim
     *
     * @param string  $name
     * @param mixed   $value
     * @param boolean $replicate
     *
     * @return Builder
     */
    protected function withRegisteredClaim(string $name, mixed $value, bool $replicate): self
    {
        $this->withClaim($name, $value);

        if ($replicate) {
            $this->headers[$name] = $this->claims[$name];
        }

        return $this;
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
        $this->headers[$name] = $this->claimFactory->create($name, $value);

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
        $this->claims[$name] = $this->claimFactory->create($name, $value);

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
     * @return Token
     */
    public function getToken(Signer $signer, Key $key): Token
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
