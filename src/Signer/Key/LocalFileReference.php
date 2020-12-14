<?php

namespace Larke\JWT\Signer\Key;

use Larke\JWT\Exception\FileCouldNotBeRead;

final class LocalFileReference
{
    private const PATH_PREFIX = 'file://';

    private string $path;
    private string $passphrase;

    private function __construct(string $path, string $passphrase)
    {
        $this->path = $path;
        $this->passphrase = $passphrase;
    }

    /** 
     * @throws FileCouldNotBeRead 
     */
    public static function file(string $path, string $passphrase = ''): self
    {
        if (strpos($path, self::PATH_PREFIX) === 0) {
            $path = substr($path, 7);
        }

        if (! file_exists($path)) {
            throw FileCouldNotBeRead::onPath($path);
        }

        return new self($path, $passphrase);
    }

    public function contents(): string
    {
        return self::PATH_PREFIX . $this->path;
    }

    public function passphrase(): string
    {
        return $this->passphrase;
    }
}
