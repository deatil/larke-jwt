<?php

declare (strict_types = 1);

namespace Larke\JWT\Signer\Key;

use Throwable;
use SplFileObject;

use Larke\JWT\Contracts\Key;
use Larke\JWT\Exception\FileCouldNotBeRead;
use Larke\JWT\Exception\CannotDecodeContent;

final class InMemory implements Key
{
    private $contents;
    private $passphrase;

    private function __construct(string $contents, string $passphrase)
    {
        $this->contents   = $contents;
        $this->passphrase = $passphrase;
    }

    public static function empty(): self
    {
        return new self('', '');
    }

    public static function plainText(string $contents, string $passphrase = ''): self
    {
        return new self($contents, $passphrase);
    }

    public static function base64Encoded(string $contents, string $passphrase = ''): self
    {
        $decoded = base64_decode($contents, true);

        if ($decoded === false) {
            throw CannotDecodeContent::invalidBase64String();
        }

        return new self($decoded, $passphrase);
    }

    /** @throws FileCouldNotBeRead */
    public static function file(string $path, string $passphrase = ''): self
    {
        try {
            $file = new SplFileObject($path);
        } catch (Throwable $exception) {
            throw FileCouldNotBeRead::onPath($path, $exception);
        }

        $contents = $file->fread($file->getSize());
        assert(is_string($contents));

        return new self($contents, $passphrase);
    }

    public function getContent(): string
    {
        return $this->contents;
    }

    public function getPassphrase(): string
    {
        return $this->passphrase;
    }
}
