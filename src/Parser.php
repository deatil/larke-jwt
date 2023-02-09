<?php

declare (strict_types = 1);

namespace Larke\JWT;

use DateTimeImmutable;
use InvalidArgumentException;

use Larke\JWT\Contracts\Decoder;
use Larke\JWT\Encoding\JoseEncoder;
use Larke\JWT\Claim\RegisteredClaims;
use Larke\JWT\Claim\Factory as ClaimFactory;
use Larke\JWT\Exception\InvalidTokenStructure;

/**
 * This class parses the JWT strings and convert them into tokens
 */
class Parser
{
    /**
     * The data decoder
     *
     * @var Decoder
     */
    private $decoder;

    /**
     * The claims factory
     *
     * @var ClaimFactory
     */
    private $claimFactory;

    private const MICROSECOND_PRECISION = 6;

    /**
     * Initializes the object
     *
     * @param Decoder      $decoder
     * @param ClaimFactory $claimFactory
     */
    public function __construct(
        Decoder $decoder = null,
        ClaimFactory $claimFactory = null
    ) {
        $this->decoder = $decoder ?: new JoseEncoder();
        $this->claimFactory = $claimFactory ?: new ClaimFactory();
    }

    /**
     * Parses the JWT and returns a token
     *
     * @param string $jwt
     *
     * @return Token
     */
    public function parse($jwt)
    {
        $data = $this->splitJwt($jwt);
        $header = $this->parseHeader($data[0]);
        $claims = $this->parseClaims($data[1]);
        $signature = $this->parseSignature($header, $data[2]);

        foreach ($claims as $name => $value) {
            if (isset($header[$name])) {
                $header[$name] = $value;
            }
        }

        if ($signature === null) {
            unset($data[2]);
        }

        return new Token($header, $claims, $signature, $data);
    }

    /**
     * Splits the JWT string into an array
     *
     * @param string $jwt
     *
     * @return array
     *
     * @throws InvalidArgumentException When JWT is not a string or is invalid
     */
    protected function splitJwt($jwt)
    {
        if (!is_string($jwt)) {
            throw new InvalidArgumentException('The JWT string must have two dots');
        }

        $data = explode('.', $jwt);

        if (count($data) != 3) {
            throw new InvalidArgumentException('The JWT string must have two dots');
        }

        return $data;
    }

    /**
     * Parses the header from a string
     *
     * @param string $data
     *
     * @return array
     *
     * @throws InvalidArgumentException When an invalid header is informed
     */
    protected function parseHeader($data)
    {
        $header = (array) $this->decoder->jsonDecode($this->decoder->base64UrlDecode($data));

        if (isset($header['enc'])) {
            throw new InvalidArgumentException('Encryption is not supported yet');
        }

        return $header;
    }

    /**
     * Parses the claim set from a string
     *
     * @param string $data
     *
     * @return array
     */
    protected function parseClaims($data)
    {
        $claims = (array) $this->decoder->jsonDecode($this->decoder->base64UrlDecode($data));

        foreach ($claims as $name => &$value) {
            if (in_array($name, RegisteredClaims::DATE_CLAIMS)) {
                $value = $this->convertDate($value);
            }
            
            $value = $this->claimFactory->create($name, $value);
        }

        return $claims;
    }

    /** @throws InvalidTokenStructure */
    private function convertDate(int|float|string $timestamp)
    {
        if (! is_numeric($timestamp)) {
            throw InvalidTokenStructure::dateIsNotParseable($timestamp);
        }

        $normalizedTimestamp = number_format((float) $timestamp, self::MICROSECOND_PRECISION, '.', '');

        $date = DateTimeImmutable::createFromFormat('U.u', $normalizedTimestamp);

        if ($date === false) {
            throw InvalidTokenStructure::dateIsNotParseable($normalizedTimestamp);
        }

        return $date;
    }

    /**
     * Returns the signature from given data
     *
     * @param array  $header
     * @param string $data
     *
     * @return Signature
     */
    protected function parseSignature(array $header, $data)
    {
        if ($data == '' || !isset($header['alg']) || $header['alg'] == 'none') {
            return null;
        }

        $hash = $this->decoder->base64UrlDecode($data);

        return new Signature($hash);
    }
}
