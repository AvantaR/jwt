<?php
declare(strict_types=1);

namespace JWT\Test\Unit;

use Generator;
use JsonException;
use JWT\JWT;
use JWT\JWTException;
use JWT\TokenDecoded;
use PHPUnit\Framework\TestCase;

class JWTTest extends TestCase
{

    public function testCreateInstance(): void
    {
        $instance = new JWT();

        $this->assertInstanceOf(JWT::class, $instance);
    }

    /**
     * @dataProvider tokenHMACDataProvider
     * @param string $token
     * @param array $expectedHeader
     * @param array $expectedPayload
     */
    public function testValidTokenDecode(string $token, array $expectedHeader, array $expectedPayload): void
    {
        $jwt = new JWT();

        $result = $jwt->decode($token);

        $this->assertInstanceOf(TokenDecoded::class, $result);
        $this->assertEquals($expectedHeader, $result->getHeader());
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
        $jwt->decode($token)->getHeader();
    }

    /**
     * @param array $header
     * @param array $payload
     * @param string $expectedToken
     * @dataProvider tokenHMACDataProvider
     */
    public function testEncode(string $expectedToken, array $header, array $payload, string $secret): void
    {
        $jwt = new JWT();

        $actualToken = $jwt->encode($header, $payload, $secret);

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
    public function tokenHMACDataProvider(): Generator
    {
        yield [
            'token' => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
            'header' => [
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
            'header' => [
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
            'header' => [
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
        yield [
            'token' => 'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.bQTnz6AuMJvmXXQsVPrxeQNvzDkimo7VNXxHeSBfClLufmCVZRUuyTwJF311JHuh',
            'header' => [
                'alg' => 'HS384',
                'typ' => 'JWT'
            ],
            'payload' => [
                'sub' => '1234567890',
                'name' => 'John Doe',
                'admin' => true,
                'iat' => 1516239022
            ],
            'secret' => 'your-384-bit-secret'
        ];
        yield [
            'token' => 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VFb0qJ1LRg_4ujbZoRMXnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxtHWKa64zDl2ofkT8F6jBt_K4riU-fPg',
            'header' => [
                'alg' => 'HS512',
                'typ' => 'JWT'
            ],
            'payload' => [
                'sub' => '1234567890',
                'name' => 'John Doe',
                'admin' => true,
                'iat' => 1516239022
            ],
            'secret' => 'your-512-bit-secret'
        ];
    }

    public function tokenRSADataProvider(): Generator
    {
        yield [
            'token' => 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA',
            'header' => [
                'alg' => 'RS256',
                'typ' => 'JWT'
            ],
            'payload' => [
                'sub' => '1234567890',
                'name' => 'John Doe',
                'admin' => true,
                'iat' => 1516239022
            ]
        ];
    }

    /**
     * @return Generator
     */
    public function signatureDataProvider(): Generator
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