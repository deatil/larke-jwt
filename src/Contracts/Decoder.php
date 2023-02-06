<?php

declare (strict_types = 1);

namespace Larke\JWT\Contracts;

use Larke\JWT\Exception\CannotDecodeContent;

interface Decoder
{
    /**
     * Decodes from JSON, validating the errors
     *
     * @param non-empty-string $json
     *
     * @throws CannotDecodeContent When something goes wrong while decoding.
     */
    public function jsonDecode(string $json): mixed;

    /**
     * Decodes from Base64URL
     *
     * @throws CannotDecodeContent When something goes wrong while decoding.
     */
    public function base64UrlDecode(string $data): string;
}
