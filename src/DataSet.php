<?php

declare(strict_types=1);

namespace Larke\JWT;

use Larke\JWT\Contracts\DataSet as BaseDataSet;

use function array_key_exists;

final class DataSet implements BaseDataSet
{
    private array $data;
    
    private string $encoded;
    
    /** @param array<non-empty-string, mixed> $data */
    public function __construct(array $data, string $encoded)
    {
        $this->data    = $data;
        $this->encoded = $encoded;
    }

    /** @param non-empty-string $name */
    public function get(string $name, mixed $default = null): mixed
    {
        return $this->data[$name] ?? $default;
    }

    /** @param non-empty-string $name */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->data);
    }

    /** @return array<non-empty-string, mixed> */
    public function all(): array
    {
        return $this->data;
    }

    public function toString(): string
    {
        return $this->encoded;
    }
}
