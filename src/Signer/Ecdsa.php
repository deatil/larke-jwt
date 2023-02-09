<?php

declare (strict_types = 1);

namespace Larke\JWT\Signer;

use Larke\JWT\Contracts\Key;
use Larke\JWT\Signer\Ecdsa\MultibyteStringConverter;
use Larke\JWT\Signer\Ecdsa\SignatureConverter;

use const OPENSSL_KEYTYPE_EC;

/**
 * Base class for ECDSA signers
 */
abstract class Ecdsa extends OpenSSL
{
    /**
     * @var SignatureConverter
     */
    private $converter;

    public function __construct(SignatureConverter $converter = null)
    {
        $this->converter = $converter ?: new MultibyteStringConverter();
    }

    /**
     * {@inheritdoc}
     */
    public function createHash(string $payload, Key $key): string
    {
        return $this->converter->fromAsn1(
            parent::createHash($payload, $key),
            $this->getKeyLength()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function doVerify(string $expected, string $payload, Key $key): bool
    {
        return parent::doVerify(
            $this->converter->toAsn1($expected, $this->getKeyLength()),
            $payload,
            $key
        );
    }

    /**
     * Returns the length of each point in the signature, so that we can calculate and verify R and S points properly
     *
     * @internal
     */
    abstract public function getKeyLength(): int;

    /**
     * {@inheritdoc}
     */
    final public function getKeyType(): string
    {
        return OPENSSL_KEYTYPE_EC;
    }
}
