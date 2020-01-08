<?php

namespace JWT;

class TokenDecoded implements TokenInterface
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
     * @param string $token
     */
    public function __construct(string $token)
    {
        [$this->header, $this->payload] = explode('.', $token);
    }

    /**
     * @return array
     */
    public function getHeader(): array
    {
        return json_decode(Base64Url::decode($this->header), true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * @return array
     */
    public function getPayload(): array
    {
        return json_decode(Base64Url::decode($this->payload), true, 512, JSON_THROW_ON_ERROR);
    }
}