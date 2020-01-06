<?php
declare(strict_types=1);

namespace JWT;

class JWT
{
    /**
     * @param string $token
     * @return JWTEncoded
     * @throws JWTException
     */
    public function decode(string $token): JWTEncoded
    {
        [$headers, $payload, $signature] = explode('.', $token);

        $headers = json_decode(base64_decode($headers), true);
        $payload = json_decode(base64_decode($payload), true);

        if (!is_array($headers) || !is_array($payload)) {
            throw new JWTException('Invalid JWT Token');
        }

        return new JWTEncoded($headers, $payload);
    }
}