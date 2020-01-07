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
     * @param array $headers
     * @param array $payload
     * @param string $expectedToken
     * @dataProvider tokenDataProvider
     */
    public function testEncode(string $expectedToken, array $headers, array $payload, string $secret): void
    {
        $jwt = new JWT();

        $actualToken = $jwt->encode($headers, $payload, $secret);

        $this->assertEquals($expectedToken, $actualToken);
    }

    /**
     * @dataProvider signatureDataProvider
     */
    public function testVerifyTokenSignature(string $secret, bool $expected): void
    {
        $jwt = new JWT();
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.kK9JnTXZwzNo3BYNXJT57PGLnQk-Xyu7IBhRWFmc4C0';
        $actual = $jwt->verify($token, $secret);

        $this->assertEquals($expected, $actual);
    }

    /**
     * @return Generator
     */
    public function tokenDataProvider(): Generator
    {
        yield [
            'token' => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
            'headers' => [
                'alg' => 'HS256',
                'typ' => 'JWT'
            ],
            'payload' => [
                'sub' => '1234567890',
                'name' => 'John Doe',
                'iat' => 1516239022
            ],
            'secret' => 'your-256-bit-secret'
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
            ],
            'secret' => 'your-256-bit-secret'
        ];
        yield [
            'token' => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjJ9.U3TsHpifbXHt3KaI8C40WLEajpCF5N6YxYOz_w3JOwM',
            'headers' => [
                'alg' => 'HS256',
                'typ' => 'JWT'
            ],
            'payload' => [
                'sub' => '1234567890',
                'name' => 'Test',
                'iat' => 1516239022
            ],
            'secret' => 'arkangdynian'
        ];
    }

    public function signatureDataProvider()
    {
        yield [
            'secret' => 'secret-key',
            'expected' => true
        ];
        yield [
            'secret' => 'invalidSecret',
            'expected' => false
        ];
    }
}