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

        $headers = json_decode(Base64Url::decode($headers), true, 512, JSON_THROW_ON_ERROR);
        $payload = json_decode(Base64Url::decode($payload), true, 512, JSON_THROW_ON_ERROR);

        if (!is_array($headers) || !is_array($payload)) {
            throw new JWTException('Invalid JWT Token');
        }

        return new JWTEncoded($headers, $payload);
    }

    /**
     * @param string $token
     * @param string $secret
     * @return bool
     */
    public function verify(string $token, string $secret): bool
    {
        [$headersEncoded, $payloadEncoded, $signatureEncoded] = explode('.', $token);
        $headers = json_decode(Base64Url::decode($headersEncoded), true, 512, JSON_THROW_ON_ERROR);
        $hashedValue = hash_hmac(Algorithms::TYPES[$headers['alg']], $headersEncoded . '.' . $payloadEncoded, $secret, true);

        return Base64Url::encode($hashedValue) === $signatureEncoded;
    }
}