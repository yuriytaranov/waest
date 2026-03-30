<?php
declare(strict_types=1);

namespace Waest;

use InvalidArgumentException;
use UnexpectedValueException;

trait PaddingTrait
{
    public static function addPadding(string $data, int $blockSize = 16): string
    {
        if ($blockSize !== 16) {
            throw new InvalidArgumentException('AES block size must be 16 bytes.');
        }

        $padLen = $blockSize - (strlen($data) % $blockSize);
        if ($padLen === 0) {
            $padLen = $blockSize;
        }

        return $data . str_repeat(chr($padLen), $padLen);
    }

    public static function removePadding(string $data, int $blockSize = 16): string
    {
        if ($blockSize !== 16) {
            throw new InvalidArgumentException('AES block size must be 16 bytes.');
        }

        $len = strlen($data);
        if ($len === 0 || ($len % $blockSize) !== 0) {
            throw new UnexpectedValueException('Invalid padded data length.');
        }

        $padLen = ord($data[$len - 1]);
        if ($padLen < 1 || $padLen > $blockSize) {
            throw new UnexpectedValueException('Invalid padding length.');
        }

        $start = $len - $padLen;
        for ($i = $start; $i < $len; $i++) {
            if (ord($data[$i]) !== $padLen) {
                throw new UnexpectedValueException('Invalid padding bytes.');
            }
        }

        return substr($data, 0, $start);
    }
}

