<?php
declare(strict_types=1);

namespace Waest\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use Waest\HKDF;

final class HKDFTest extends TestCase
{
    /**
     * RFC 5869 test vectors (HKDF-SHA256), using PRK directly for expand().
     */
    public function testExpandMatchesRfc5869TestCase1(): void
    {
        $prk = hex2bin('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
        self::assertNotFalse($prk);

        $info = hex2bin('f0f1f2f3f4f5f6f7f8f9');
        self::assertNotFalse($info);

        $okm = HKDF::expand($prk, 42, $info);
        self::assertSame(
            '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
            bin2hex($okm),
        );
    }

    public function testExpandMatchesRfc5869TestCase2(): void
    {
        $prk = hex2bin('06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244');
        self::assertNotFalse($prk);

        $info = hex2bin('b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
        self::assertNotFalse($info);

        $okm = HKDF::expand($prk, 82, $info);
        self::assertSame(
            'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87',
            bin2hex($okm),
        );
    }

    public function testExpandMatchesRfc5869TestCase3(): void
    {
        $prk = hex2bin('19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04');
        self::assertNotFalse($prk);

        $info = '';

        $okm = HKDF::expand($prk, 42, $info);
        self::assertSame(
            '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
            bin2hex($okm),
        );
    }

    public function testInfoForTypeNormalizesAndRejectsUnknown(): void
    {
        self::assertSame('WhatsApp Image Keys', HKDF::infoForType(' image '));
        self::assertSame('WhatsApp Video Keys', HKDF::infoForType("\nVIDEO\t"));
        self::assertSame('WhatsApp Audio Keys', HKDF::infoForType('AuDiO'));
        self::assertSame('WhatsApp Document Keys', HKDF::infoForType('document'));

        $this->expectException(InvalidArgumentException::class);
        HKDF::infoForType('UNKNOWN');
    }

    /**
     * @throws RandomException
     */
    public function testExpand112ForTypeReturns112Bytes(): void
    {
        $prk = random_bytes(32);
        $out = HKDF::expand112ForType($prk, 'IMAGE');
        self::assertSame(112, strlen($out));
    }

    /**
     * @throws RandomException
     */
    public function testExpandHandlesZeroAndRejectsInvalidLengths(): void
    {
        $prk = random_bytes(32);
        self::assertSame('', HKDF::expand($prk, 0, ''));

        $this->expectException(InvalidArgumentException::class);
        HKDF::expand($prk, -1, '');
    }

    /**
     * @throws RandomException
     */
    public function testExpandRejectsTooLargeLength(): void
    {
        $prk = random_bytes(32);

        $this->expectException(InvalidArgumentException::class);
        HKDF::expand($prk, 255 * 32 + 1, '');
    }
}

