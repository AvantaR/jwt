<?php

namespace JWT;

class TokenEncoded implements TokenInterface
{
    /**
     * @var string
     */
    private $header;

    /**
     * @var string
     */
    private $payload;

    /**
     * @var string
     */
    private $signature;

    /**
     * @param string $token
     */
    public function __construct(string $token)
    {
        [$this->header, $this->payload, $this->signature] = explode('.', $token);
    }

    /**
     * @return string
     */
    public function getHeader(): string
    {
        return $this->header;
    }

    /**
     * @return string
     */
    public function getPayload(): string
    {
        return $this->payload;
    }

    /**
     * @return string
     */
    public function getSignature(): string
    {
        return $this->signature;
    }
}