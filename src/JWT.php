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
     * @param array $header
     * @param array $payload
     * @param string $secret
     * @return string
     */
    public function encode(array $header, array $payload, string $secret): string
    {

        $headerEncoded = Base64Url::encode(json_encode($header));
        $payloadEncoded = Base64Url::encode(json_encode($payload));

        $signatureEncoded = Base64Url::encode($this->sign($headerEncoded, $payloadEncoded, Algorithms::TYPES[$header['alg']], $secret));

        return implode('.', [$headerEncoded, $payloadEncoded, $signatureEncoded]);
    }

    /**
     * @param string $headerEncoded
     * @param string $payloadEncoded
     * @param string $algorithm
     * @param string $secret
     * @return string
     */
    private function sign(string $headerEncoded, string $payloadEncoded, string $algorithm, string $secret): string
    {
        return hash_hmac($algorithm, implode('.', [$headerEncoded, $payloadEncoded]), $secret, true);
    }

    /**
     * @param string $token
     * @param string $secret
     * @return bool
     */
    public function verify(string $token, string $secret): bool
    {
        [$headerEncoded, $payloadEncoded, $signatureEncoded] = explode('.', $token);
        $headers = json_decode(Base64Url::decode($headerEncoded), true, 512, JSON_THROW_ON_ERROR);
        $hashedValue = hash_hmac(Algorithms::TYPES[$headers['alg']], implode('.', [$headerEncoded, $payloadEncoded]), $secret, true);

        return Base64Url::encode($hashedValue) === $signatureEncoded;
    }
}