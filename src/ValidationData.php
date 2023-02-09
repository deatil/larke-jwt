<?php

declare (strict_types = 1);

namespace Larke\JWT;

use DateTimeImmutable;

use Larke\JWT\Clock\SystemClock;
use Larke\JWT\Claim\RegisteredClaims;

/**
 * Class that wraps validation values
 */
class ValidationData
{
    /**
     * The list of things to be validated
     *
     * @var array
     */
    private $items;

    /**
     * The leeway (in seconds) to use when validating time claims
     * @var int
     */
    private $leeway;

    /**
     * Initializes the object
     *
     * @param DateTimeImmutable $currentTime
     * @param int               $leeway
     */
    public function __construct(DateTimeImmutable $currentTime = null, int $leeway = 0)
    {
        $currentTime  = $currentTime ?: SystemClock::fromSystemTimezone()->now();
        $this->leeway = $leeway;

        $this->items = [
            RegisteredClaims::ID       => null,
            RegisteredClaims::ISSUER   => null,
            RegisteredClaims::AUDIENCE => null,
            RegisteredClaims::SUBJECT  => null
        ];

        $this->currentTime($currentTime);
    }

    /**
     * Configures the id
     *
     * @param string $id
     */
    public function identifiedBy(string $id)
    {
        $this->items[RegisteredClaims::ID] = $id;
    }

    /**
     * Configures the issuer
     *
     * @param string $issuer
     */
    public function issuedBy(string $issuer)
    {
        $this->items[RegisteredClaims::ISSUER] = $issuer;
    }

    /**
     * Configures the audience
     *
     * @param string $audience
     */
    public function permittedFor(string $audience)
    {
        $this->items[RegisteredClaims::AUDIENCE] = $audience;
    }

    /**
     * Configures the subject
     *
     * @param string $subject
     */
    public function relatedTo(string $subject)
    {
        $this->items[RegisteredClaims::SUBJECT] = $subject;
    }

    /**
     * Configures the time that "iat", "nbf" and "exp" should be based on
     *
     * @param DateTimeImmutable $currentTime
     */
    public function currentTime(DateTimeImmutable $currentTime)
    {
        $leeway = $this->leeway;
        
        $this->items[RegisteredClaims::ISSUED_AT]       = $currentTime->modify("+{$leeway} second");
        $this->items[RegisteredClaims::NOT_BEFORE]      = $currentTime->modify("+{$leeway} second");
        $this->items[RegisteredClaims::EXPIRATION_TIME] = $currentTime->modify("-{$leeway} second");
    }

    /**
     * Returns the requested item
     *
     * @param string $name
     *
     * @return mixed
     */
    public function get($name)
    {
        return isset($this->items[$name]) ? $this->items[$name] : null;
    }

    /**
     * Returns if the item is present
     *
     * @param string $name
     *
     * @return boolean
     */
    public function has($name)
    {
        return !empty($this->items[$name]);
    }
}
