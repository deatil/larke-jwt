<?php

declare (strict_types = 1);

namespace Larke\JWT\Signer;

use const OPENSSL_KEYTYPE_RSA;

/**
 * Base class for RSASSA-PKCS1 signers
 */
abstract class Rsa extends OpenSSL
{
    final public function getKeyType(): int
    {
        return OPENSSL_KEYTYPE_RSA;
    }
}
