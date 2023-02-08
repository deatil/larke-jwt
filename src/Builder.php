<?php

declare (strict_types = 1);

namespace Larke\JWT;

use Larke\JWT\Contracts\Key;
use Larke\JWT\Contracts\Signer;
use Larke\JWT\Contracts\Encoder;
use Larke\JWT\Encoding\JoseEncoder;
use Larke\JWT\Claim\Factory as ClaimFactory;
use Larke\JWT\Claim\RegisteredClaims;
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
    private $headers = [
        'typ' => 'JWT', 
        'alg' => 'none'
    ];

    /**
     * The token claim set
     *
     * @var array
     */
    private $claims = [];

    /**
     * The data encoder
     *
     * @var Encoder
     */
    private $encoder;

    /**
     * The factory of claims
     *
     * @var ClaimFactory
     */
    private $claimFactory;

    /**
     * The formatter of claims
     *
     * @var ClaimsFormatter
     */
    private $claimFormatter;

    /**
     * @var Signer|null
     */
    private $signer;

    /**
     * @var Key|null
     */
    private $key;

    /**
     * Initializes a new builder
     *
     * @param Encoder $encoder
     * @param ClaimFactory $claimFactory
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
    public function permittedFor($audience, $replicateAsHeader = false)
    {
        return $this->withRegisteredClaim(RegisteredClaims::AUDIENCE, (string) $audience, $replicateAsHeader);
    }

    /**
     * Configures the expiration time, expirTime
     *
     * @param int     $expiration
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function expiresAt($expiration, $replicateAsHeader = false)
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
    public function identifiedBy($id, $replicateAsHeader = false)
    {
        return $this->withRegisteredClaim(RegisteredClaims::ID, (string) $id, $replicateAsHeader);
    }

    /**
     * Configures the time that the token was issued
     *
     * @param int     $issuedAt
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function issuedAt($issuedAt, $replicateAsHeader = false)
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
    public function issuedBy($issuer, $replicateAsHeader = false)
    {
        return $this->withRegisteredClaim(RegisteredClaims::ISSUER, (string) $issuer, $replicateAsHeader);
    }

    /**
     * Configures the time before which the token cannot be accepted
     *
     * @param int     $notBefore
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function canOnlyBeUsedAfter($notBefore, $replicateAsHeader = false)
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
    public function relatedTo($subject, $replicateAsHeader = false)
    {
        return $this->withRegisteredClaim(RegisteredClaims::SUBJECT, (string) $subject, $replicateAsHeader);
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
    protected function withRegisteredClaim($name, $value, $replicate)
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
    public function withHeader($name, $value)
    {
        $this->headers[(string) $name] = $this->claimFactory->create($name, $value);

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
    public function withClaim($name, $value)
    {
        $this->claims[(string) $name] = $this->claimFactory->create($name, $value);

        return $this;
    }
    
    /**
     * Returns the encoded data
     *
     * @param array $data
     *
     * @return string
     */
    private function encode(array $data)
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
    public function getToken(Signer $signer = null, Key $key = null)
    {
        $signer = $signer ?: $this->signer;
        $key = $key ?: $this->key;

        if ($signer instanceof Signer) {
            $signer->modifyHeader($this->headers);
        }
        
        $formatedClaims = $this->claimFormatter->formatClaims($this->claims);

        $payload = [
            $this->encode($this->headers),
            $this->encode($formatedClaims)
        ];

        $signature = $this->createSignature($payload, $signer, $key);

        if ($signature !== null) {
            $payload[] = $this->encoder->base64UrlEncode((string) $signature);
        }

        return new Token($this->headers, $this->claims, $signature, $payload);
    }

    /**
     * @param string[] $payload
     *
     * @return Signature|null
     */
    private function createSignature(array $payload, Signer $signer = null, Key $key = null)
    {
        if ($signer === null || $key === null) {
            return null;
        }

        return $signer->sign(implode('.', $payload), $key);
    }
}
