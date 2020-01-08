<?php
declare(strict_types=1);

namespace JWT;

class JWTDecoded
{
    private $headers;
    private $payload;

    /**
     * JWTEncoded constructor.
     * @param array $headers
     * @param array $payload
     */
    public function __construct(array $headers, array $payload)
    {
        $this->headers = $headers;
        $this->payload = $payload;
    }

    /**
     * @return array
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    /**
     * @return array
     */
    public function getPayload(): array
    {
        return $this->payload;
    }
}