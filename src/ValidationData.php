<?php

declare (strict_types = 1);

namespace Larke\JWT;

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
     * @param int $currentTime
     * @param int $leeway
     */
    public function __construct($currentTime = null, $leeway = 0)
    {
        $currentTime  = $currentTime ?: time();
        $this->leeway = (int) $leeway;

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
    public function identifiedBy($id)
    {
        $this->items[RegisteredClaims::ID] = (string) $id;
    }

    /**
     * Configures the issuer
     *
     * @param string $issuer
     */
    public function issuedBy($issuer)
    {
        $this->items[RegisteredClaims::ISSUER] = (string) $issuer;
    }

    /**
     * Configures the audience
     *
     * @param string $audience
     */
    public function permittedFor($audience)
    {
        $this->items[RegisteredClaims::AUDIENCE] = (string) $audience;
    }

    /**
     * Configures the subject
     *
     * @param string $subject
     */
    public function relatedTo($subject)
    {
        $this->items[RegisteredClaims::SUBJECT] = (string) $subject;
    }

    /**
     * Configures the time that "iat", "nbf" and "exp" should be based on
     *
     * @param int $currentTime
     */
    public function currentTime($currentTime)
    {
        $currentTime  = (int) $currentTime;

        $this->items[RegisteredClaims::ISSUED_AT]       = $currentTime + $this->leeway;
        $this->items[RegisteredClaims::NOT_BEFORE]      = $currentTime + $this->leeway;
        $this->items[RegisteredClaims::EXPIRATION_TIME] = $currentTime - $this->leeway;
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
