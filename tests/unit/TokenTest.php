<?php

namespace JWT\Test\Unit;

use JWT\Token;
use JWT\TokenDecoded;
use JWT\TokenEncoded;
use PHPUnit\Framework\TestCase;

class TokenTest extends TestCase
{
    public function testExtractEncodedElementsFromToken(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        $tokenEncoded = new TokenEncoded($token);

        $expectedHeader = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
        $expectedPayload = 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ';
        $expectedSignature = 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

        $this->assertEquals($expectedHeader, $tokenEncoded->getHeader());
        $this->assertEquals($expectedPayload, $tokenEncoded->getPayload());
        $this->assertEquals($expectedSignature, $tokenEncoded->getSignature());
    }

    public function testExtractDecodedElementsFromToken(): void{
        $tokenString = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        $token = new TokenDecoded($tokenString);

        $expectedHeader = [
            'alg' => 'HS256',
            'typ' => 'JWT'
        ];

        $expectedPayload = [
                'sub' => '1234567890',
                'name' => 'John Doe',
                'iat' => 1516239022
        ];

        $this->assertEquals($expectedHeader, $token->getHeader());
        $this->assertEquals($expectedPayload, $token->getPayload());
    }
}