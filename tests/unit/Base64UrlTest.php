<?php
declare(strict_types=1);

namespace JWT\Test\Unit;

use JWT\Base64Url;
use PHPUnit\Framework\TestCase;

class Base64UrlTest extends TestCase
{
    public function testEncode(): void
    {
        $actual = Base64Url::encode('https://jwt.io');
        $expected = 'aHR0cHM6Ly9qd3QuaW8';

        $this->assertEquals($expected, $actual);
    }

    public function testDecode(): void
    {
        $actual = Base64Url::decode('aHR0cHM6Ly9qd3QuaW8');
        $expected = 'https://jwt.io';

        $this->assertEquals($expected, $actual);
    }
}
