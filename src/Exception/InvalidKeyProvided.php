<?php

namespace Larke\JWT\Exception;

use InvalidArgumentException;

final class InvalidKeyProvided 
    extends InvalidArgumentException 
    implements Exception
{
    public static function creatingSignatureError(string $details)
    {
        return new self('There was an error while creating the signature: ' . $details);
    }

    public static function cannotBeParsed(string $details)
    {
        return new self('It was not possible to parse your key, reason: ' . $details);
    }

    public static function incompatibleKey()
    {
        return new self('This key is not compatible with this signer');
    }
}