<?php

namespace JWT;

interface TokenInterface
{
    public function getHeader();

    public function getPayload();
}