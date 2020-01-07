<?php
declare(strict_types=1);

namespace JWT\Test\Unit;

use Generator;
use JsonException;
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

    /**
     * @dataProvider tokenDataProvider
     * @param string $token
     * @param array $expectedHeaders
     * @param array $expectedPayload
     * @throws JWTException
     */
    public function testValidTokenDecode(string $token, array $expectedHeaders, array $expectedPayload): void
    {
        $jwt = new JWT();

        $result = $jwt->decode($token);

        $this->assertInstanceOf(JWTEncoded::class, $result);
        $this->assertEquals($expectedHeaders, $result->getHeaders());
        $this->assertEquals($expectedPayload, $result->getPayload());
    }

    /**
     * @throws JWTException
     */
    public function testInvalidTokenDecode(): void
    {
        $jwt = new JWT();

        $token = 'eyJhbGciOiJIUzI231InR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

        $this->expectException(JsonException::class);
        $jwt->decode($token);
    }

    /**
     * @dataProvider signatureDataProvider
     */
    public function testVerifyTokenSignature(string $secret, bool $expected): void
    {
        $jwt = new JWT();
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA';
        $actual = $jwt->verify($token, $secret);

        $this->assertEquals($expected, $actual);
    }

    /**
     * @return Generator
     */
    public function tokenDataProvider(): Generator
    {
        yield [
            'token' => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
                        eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
                        SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
            'headers' => [
                'alg' => 'HS256',
                'typ' => 'JWT'
            ],
            'payload' => [
                'sub' => '1234567890',
                'name' => 'John Doe',
                'iat' => 1516239022
            ]
        ];
        yield [
            'token' => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2NjYiLCJuYW1lIjoiSm9zZSBQb3BlIiwibmlja25hbWUiOiJQYXBhIn0.aFyJqWf-7R1uxnVvkGiu5s3TL7QSyQB19gdygmY4Bu8',
            'headers' => [
                'alg' => 'HS256',
                'typ' => 'JWT'
            ],
            'payload' => [
                'sub' => '666',
                'name' => 'Jose Pope',
                'nickname' => 'Papa'
            ]
        ];
    }

    public function signatureDataProvider()
    {
        yield [
            'secret' => 'test',
            'expected' => true
        ];
        yield [
            'secret' => 'invalidSecret',
            'expected' => false
        ];
    }
}