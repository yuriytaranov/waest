<?php
declare(strict_types=1);

namespace Waest\Tests;

use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use RuntimeException;
use Waest\DecryptingStream;
use Waest\EncryptingStream;
use Waest\HKDF;
use Waest\PaddingTrait;

final class DecryptingStreamTest extends TestCase
{
    use PaddingTrait;

    /**
     * @throws RandomException
     */
    public function testRoundTripAllMediaTypes(): void
    {
        foreach (['IMAGE', 'VIDEO', 'AUDIO', 'DOCUMENT'] as $mediaType) {
            $mediaKey = random_bytes(32);
            $plain = random_bytes(12345);

            $out = Utils::streamFor('');
            $enc = new EncryptingStream($out, $mediaKey, $mediaType);
            $enc->write($plain);
            $enc->close();

            $out->rewind();
            $dec = new DecryptingStream($out, $mediaKey, $mediaType);
            self::assertSame($plain, $dec->getContents(), "round-trip for {$mediaType}");
        }
    }

    /**
     * @throws RandomException
     */
    public function testRoundTripEmptyPlaintext(): void
    {
        $mediaKey = random_bytes(32);
        $out = Utils::streamFor('');
        $enc = new EncryptingStream($out, $mediaKey, 'IMAGE');
        $enc->close();

        $out->rewind();
        $dec = new DecryptingStream($out, $mediaKey, 'IMAGE');
        self::assertSame('', $dec->getContents());
    }

    /**
     * @throws RandomException
     */
    public function testMacFailureThrows(): void
    {
        $mediaKey = random_bytes(32);
        $out = Utils::streamFor('');
        $enc = new EncryptingStream($out, $mediaKey, 'IMAGE');
        $enc->write('secret data');
        $enc->close();

        $out->rewind();
        $blob = $out->getContents();
        self::assertGreaterThan(10, strlen($blob));
        $corrupt = substr($blob, 0, -1) . 'X';
        $badStream = Utils::streamFor($corrupt);

        $dec = new DecryptingStream($badStream, $mediaKey, 'IMAGE');
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('MAC verification failed.');
        $dec->getContents();
    }

    /**
     * @throws RandomException
     */
    public function testWrongKeyThrowsMacOrDecryptFailure(): void
    {
        $mediaKey = random_bytes(32);
        $wrongKey = random_bytes(32);
        self::assertNotSame($mediaKey, $wrongKey);

        $out = Utils::streamFor('');
        $enc = new EncryptingStream($out, $mediaKey, 'IMAGE');
        $enc->write('x');
        $enc->close();

        $out->rewind();
        $dec = new DecryptingStream($out, $wrongKey, 'IMAGE');
        $this->expectException(RuntimeException::class);
        $dec->getContents();
    }

    /**
     * @throws RandomException
     */
    public function testDecryptMatchesReferenceFromReadmeAlgorithm(): void
    {
        $mediaKey = random_bytes(32);
        $mediaType = 'VIDEO';
        $plain = random_bytes(8000);

        $out = Utils::streamFor('');
        $enc = new EncryptingStream($out, $mediaKey, $mediaType);
        $enc->write($plain);
        $enc->close();
        $out->rewind();
        $cipherMac = $out->getContents();

        $expanded = HKDF::expand112ForType($mediaKey, $mediaType);
        $iv = substr($expanded, 0, 16);
        $cipherKey = substr($expanded, 16, 32);
        $macKey = substr($expanded, 48, 32);

        $cipher = substr($cipherMac, 0, -10);
        $mac = substr($cipherMac, -10);
        self::assertSame(
            $mac,
            substr(hash_hmac('sha256', $iv . $cipher, $macKey, true), 0, 10),
        );

        $padded = openssl_decrypt(
            $cipher,
            'aes-256-cbc',
            $cipherKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv,
        );
        self::assertNotFalse($padded);
        $refPlain = self::removePadding($padded, 16);

        $out->rewind();
        $dec = new DecryptingStream($out, $mediaKey, $mediaType);
        self::assertSame($refPlain, $dec->getContents());
    }

    /**
     * @throws RandomException
     */
    public function testReadAndSeekOnPlaintextView(): void
    {
        $mediaKey = random_bytes(32);
        $plain = 'hello world';
        $out = Utils::streamFor('');
        $enc = new EncryptingStream($out, $mediaKey, 'DOCUMENT');
        $enc->write($plain);
        $enc->close();

        $out->rewind();
        $dec = new DecryptingStream($out, $mediaKey, 'DOCUMENT');
        self::assertSame('hel', $dec->read(3));
        self::assertSame(3, $dec->tell());
        self::assertSame('lo ', $dec->read(3));
        $dec->seek(6);
        self::assertSame('world', $dec->read(10));
        self::assertTrue($dec->eof());
    }

    public function testWriteThrows(): void
    {
        $dec = new DecryptingStream(Utils::streamFor(''), random_bytes(32), 'IMAGE');
        $this->expectException(RuntimeException::class);
        $dec->write('x');
    }
}
