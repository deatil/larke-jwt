<?php

declare (strict_types = 1);

namespace Larke\JWT\Signer;

use Larke\JWT\Signer;
use Larke\JWT\Contracts\Key;
use Larke\JWT\Exception\InvalidKeyProvided;

use function assert;
use function is_array;
use function is_resource;
use function openssl_error_string;
use function openssl_free_key;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;

abstract class OpenSSL extends BaseSigner
{
    public function createHash(string $payload, Key $key): string
    {
        $privateKey = $this->getPrivateKey($key->getContent(), $key->getPassphrase());

        try {
            $signature = '';

            if (! openssl_sign($payload, $signature, $privateKey, $this->getAlgorithm())) {
                throw InvalidKeyProvided::creatingSignatureError(openssl_error_string());
            }

            return $signature;
        } finally {
            openssl_free_key($privateKey);
        }
    }

    /**
     * @param string $pem
     * @param string $passphrase
     *
     * @return resource
     */
    private function getPrivateKey(string $pem, string $passphrase)
    {
        $privateKey = openssl_pkey_get_private($pem, $passphrase);
        $this->validateKey($privateKey);

        return $privateKey;
    }

    /**
     * @param string $expected
     * @param string $payload
     * @param Key    $key
     * @return bool
     */
    public function doVerify(string $expected, string $payload, Key $key): bool
    {
        $publicKey = $this->getPublicKey($key->getContent());
        $result    = openssl_verify($payload, $expected, $publicKey, $this->getAlgorithm());
        openssl_free_key($publicKey);

        return $result === 1;
    }

    /**
     * @param string $pem
     *
     * @return resource
     */
    private function getPublicKey(string $pem)
    {
        $publicKey = openssl_pkey_get_public($pem);
        $this->validateKey($publicKey);

        return $publicKey;
    }

    /**
     * Raises an exception when the key type is not the expected type
     *
     * @param resource|bool $key
     *
     * @throws InvalidArgumentException
     */
    private function validateKey(mixed $key)
    {
        if (is_bool($key)) {
            throw InvalidKeyProvided::cannotBeParsed(openssl_error_string());
        }

        $details = openssl_pkey_get_details($key);

        if (! isset($details['key']) || $details['type'] !== $this->getKeyType()) {
            throw InvalidKeyProvided::incompatibleKey();
        }
    }

    /**
     * Returns the type of key to be used to create/verify the signature (using OpenSSL constants)
     *
     * @internal
     */
    abstract public function getKeyType(): string;

    /**
     * Returns which algorithm to be used to create/verify the signature (using OpenSSL constants)
     *
     * @internal
     */
    abstract public function getAlgorithm(): string;
}
