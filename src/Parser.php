<?php

declare (strict_types = 1);

namespace Larke\JWT;

use DateTimeImmutable;
use InvalidArgumentException;

use Larke\JWT\Contracts\Decoder;
use Larke\JWT\Contracts\UnencryptedToken;
use Larke\JWT\Encoding\JoseEncoder;
use Larke\JWT\Claim\RegisteredClaims;
use Larke\JWT\Claim\RegisteredHeaders;
use Larke\JWT\Exception\InvalidTokenStructure;

use function explode;
use function in_array;
use function is_numeric;
use function array_key_exists;

/**
 * This class parses the JWT strings and convert them into tokens
 */
final class Parser
{
    /**
     * The data decoder
     *
     * @var Decoder
     */
    private Decoder $decoder;

    private const MICROSECOND_PRECISION = 6;

    /**
     * Initializes the object
     *
     * @param Decoder      $decoder
     */
    public function __construct(
        ?Decoder $decoder = null,
    ) {
        $this->decoder = $decoder ?: new JoseEncoder();
    }

    /**
     * Parses the JWT and returns a token
     *
     * @param string $jwt
     *
     * @return UnencryptedToken
     */
    public function parse(string $jwt): UnencryptedToken
    {
        [$encodedHeaders, $encodedClaims, $encodedSignature] = $this->splitJwt($jwt);
        
        $header = $this->parseHeader($encodedHeaders);
        $claims = $this->parseClaims($encodedClaims);

        return new Token(
            new DataSet($header, $encodedHeaders),
            new DataSet($claims, $encodedClaims),
            $this->parseSignature($encodedSignature)
        );
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
    protected function splitJwt(string $jwt): array
    {
        $data = explode('.', $jwt);

        if (count($data) != 3) {
            throw InvalidTokenStructure::missingOrNotEnoughSeparators();
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
    protected function parseHeader(string $data): array
    {
        $header = $this->decode($data);

        if (! is_array($header)) {
            throw InvalidTokenStructure::arrayExpected('headers');
        }

        $this->guardAgainstEmptyStringKeys($header, 'headers');

        if (isset($header[RegisteredHeaders::ENCRYPTION])) {
            throw new InvalidArgumentException('Encryption is not supported yet');
        }
        
        if (! array_key_exists(RegisteredHeaders::TYPE, $header)) {
            $header[RegisteredHeaders::TYPE] = 'JWT';
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
    protected function parseClaims(string $data): array
    {
        $claims = $this->decode($data);

        if (! is_array($claims)) {
            throw InvalidTokenStructure::arrayExpected('claims');
        }

        $this->guardAgainstEmptyStringKeys($claims, 'claims');

        foreach ($claims as $name => &$value) {
            if (in_array($name, RegisteredClaims::DATE_CLAIMS)) {
                $value = $this->convertDate($value);
            }
        }

        return $claims;
    }
    
    /**
     * Returns the decoded data
     *
     * @param string $data
     *
     * @return array
     */
    private function decode(string $data): array
    {
        return $this->decoder->jsonDecode(
            $this->decoder->base64UrlDecode($data)
        );
    }

    /**
     * @param array<string, mixed> $array
     * @param non-empty-string     $part
     *
     * @phpstan-assert array<non-empty-string, mixed> $array
     */
    private function guardAgainstEmptyStringKeys(array $array, string $part): void
    {
        foreach ($array as $key => $value) {
            if ($key === '') {
                throw InvalidTokenStructure::arrayExpected($part);
            }
        }
    }
    
    /** @throws InvalidTokenStructure */
    private function convertDate(int|float|string $timestamp): DateTimeImmutable
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
     * @param string $data
     *
     * @return Signature
     */
    protected function parseSignature(string $data): Signature
    {
        $hash = $this->decoder->base64UrlDecode($data);

        return new Signature($hash, $data);
    }
}
