<?php
declare(strict_types=1);

namespace Waest\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use UnexpectedValueException;
use Waest\PaddingTrait;

final class PaddingTraitTest extends TestCase
{
    use PaddingTrait;

    /**
     * @throws RandomException
     */
    public function testAddPaddingAndRemovePaddingRoundTrip(): void
    {
        foreach ([0, 1, 15, 16, 17, 31, 32, 33, 4096] as $len) {
            $plain = $len === 0 ? '' : random_bytes($len);
            $padded = self::addPadding($plain, 16);

            self::assertNotSame('', $padded);
            self::assertSame(0, strlen($padded) % 16);
            self::assertSame($plain, self::removePadding($padded, 16));
        }
    }

    /**
     * @throws RandomException
     */
    public function testAddPaddingAlwaysAddsAFullBlockWhenAligned(): void
    {
        $plain = random_bytes(16);
        $padded = self::addPadding($plain, 16);
        self::assertSame(32, strlen($padded));
        self::assertSame($plain, self::removePadding($padded, 16));
    }

    public function testAddPaddingRejectsNonAesBlockSize(): void
    {
        $this->expectException(InvalidArgumentException::class);
        self::addPadding('abc', 8);
    }

    public function testRemovePaddingRejectsNonAesBlockSize(): void
    {
        $this->expectException(InvalidArgumentException::class);
        self::removePadding('1234567890abcdef', 8);
    }

    public function testRemovePaddingRejectsEmptyOrNonBlockAligned(): void
    {
        $this->expectException(UnexpectedValueException::class);
        self::removePadding('', 16);
    }

    public function testRemovePaddingRejectsInvalidPadLengthByte(): void
    {
        $data = str_repeat('A', 16 - 1) . chr(0); // padLen = 0 (invalid)
        $this->expectException(UnexpectedValueException::class);
        self::removePadding($data, 16);
    }

    public function testRemovePaddingRejectsInvalidPadBytes(): void
    {
        // 32 bytes total (block-aligned), but padding bytes don't match pad length.
        $bad = str_repeat('A', 28) . "\x04\x04\x04\x05";
        self::assertSame(32, strlen($bad));

        $this->expectException(UnexpectedValueException::class);
        self::removePadding($bad, 16);
    }
}

