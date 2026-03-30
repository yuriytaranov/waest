<?php
declare(strict_types=1);

namespace Waest;

use InvalidArgumentException;

final class HKDF
{
    public const int LENGTH = 112;

    public static function expand112ForType(string $prk, string $type): string
    {
        return self::expand($prk, self::LENGTH, self::infoForType($type));
    }

    public static function infoForType(string $type): string
    {
        $type = strtoupper(trim($type));

        return match ($type) {
            'IMAGE' => 'WhatsApp Image Keys',
            'VIDEO' => 'WhatsApp Video Keys',
            'AUDIO' => 'WhatsApp Audio Keys',
            'DOCUMENT' => 'WhatsApp Document Keys',
            default => throw new InvalidArgumentException("Unknown HKDF info type: {$type}"),
        };
    }

    public static function expand(
        string $prk,
        int $length,
        string $info = '',
    ): string {
        if ($length < 0) {
            throw new InvalidArgumentException('HKDF expand length must be >= 0.');
        }

        if ($length === 0) {
            return '';
        }

        $hashLen = 32; // SHA-256 output length in bytes
        $maxLength = 255 * $hashLen; // RFC 5869
        if ($length > $maxLength) {
            throw new InvalidArgumentException("HKDF expand length must be <= {$maxLength} for sha256.");
        }

        $n = (int) ceil($length / $hashLen);

        $t = '';
        $okm = '';
        for ($i = 1; $i <= $n; $i++) {
            $t = hash_hmac('sha256', $t . $info . chr($i), $prk, true);
            $okm .= $t;
        }

        return substr($okm, 0, $length);
    }
}

