<?php

namespace JWT;

class Base64Url
{

    /**
     * @param string $value
     * @return string
     */
    public static function encode(string $value): string
    {
        return str_replace(['+','/','='], ['-','_',''], base64_encode($value));

    }

    /**
     * @param string $value
     * @return string
     */
    public static function decode(string $value): string
    {
        return base64_decode(str_replace(['-','_'], ['+','/'], $value));
    }

}