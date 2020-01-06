<?php
declare(strict_types=1);

namespace JWT\Test\Unit;

use JWT\JWT;
use JWT\JWTEncoded;
use JWT\JWTException;
use PHPUnit\Framework\TestCase;

class JWTTest extends TestCase
{

    public function testCreateInstance()
    {
        $instance = new JWT();

        $this->assertInstanceOf(JWT::class, $instance);
    }

    public function testValidTokenDecode()
    {
        $jwt = new JWT();

        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

        $expectedHeaders = [
            'alg' => 'HS256',
            'typ' => 'JWT'
        ];
        $expectedPayload = [
            'sub' => '1234567890',
            'name' => 'John Doe',
            'iat' => 1516239022
        ];

        $result = $jwt->decode($token);

        $this->assertInstanceOf(JWTEncoded::class, $result);
        $this->assertEquals($expectedHeaders, $result->getHeaders());
        $this->assertEquals($expectedPayload, $result->getPayload());
    }


    public function testValidTokenDecodeWithDifferentData()
    {
        $jwt = new JWT();

        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gUG9wZSIsImlhdCI6MTUxNjIzOTAyMn0.9dLgumnL29znlXoIa2o3I2L3g7C1ZU7nCZ_On8eKW_8';

        $expectedHeaders = [
            'alg' => 'HS256',
            'typ' => 'JWT'
        ];
        $expectedPayload = [
            'sub' => '1234567890',
            'name' => 'John Pope',
            'iat' => 1516239022
        ];

        $result = $jwt->decode($token);

        $this->assertInstanceOf(JWTEncoded::class, $result);
        $this->assertEquals($expectedHeaders, $result->getHeaders());
        $this->assertEquals($expectedPayload, $result->getPayload());
    }


    /**
     * @throws JWTException
     */
    public function testInvalidTokenDecode()
    {
        $jwt = new JWT();

        $token = 'eyJhbGciOiJIUzI231InR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

        $this->expectException(JWTException::class);
        $jwt->decode($token);
    }

}