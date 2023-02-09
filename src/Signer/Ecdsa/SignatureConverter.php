<?php

declare (strict_types = 1);

namespace Larke\JWT\Signer\Ecdsa;

interface SignatureConverter
{
    /**
     * Converts the signature generated by OpenSSL into what JWA defines
     *
     * @param string $signature
     * @param int $length
     *
     * @return string
     */
    public function fromAsn1(string $signature, int $length): string;

    /**
     * Converts the JWA signature into something OpenSSL understands
     *
     * @param string $points
     * @param int $length
     *
     * @return string
     */
    public function toAsn1(string $points, int $length): string;
}
