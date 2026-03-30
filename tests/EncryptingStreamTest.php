<?php
declare(strict_types=1);

namespace Waest\Tests;

use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use Waest\EncryptingStream;
use Waest\HKDF;
use Waest\PaddingTrait;

final class EncryptingStreamTest extends TestCase
{
    use PaddingTrait;

    /**
     * @throws RandomException
     */
    public function testEncryptingStreamWritesCiphertextAndMacAtEndWithChunkedWrites(): void
    {
        $mediaKey = random_bytes(32);
        $mediaType = 'IMAGE';

        $plain = random_bytes(4096 + 7);
        $chunks = [
            substr($plain, 0, 1),
            substr($plain, 1, 17),
            substr($plain, 18, 31),
            substr($plain, 49, 1024),
            substr($plain, 1073),
        ];

        $out = Utils::streamFor('');
        $enc = new EncryptingStream($out, $mediaKey, $mediaType);

        $total = 0;
        foreach ($chunks as $c) {
            $total += $enc->write($c);
        }
        self::assertSame(strlen($plain), $total);

        $enc->close();

        $out->rewind();
        $all = $out->getContents();

        $expanded = HKDF::expand112ForType($mediaKey, $mediaType);
        $iv = substr($expanded, 0, 16);
        $cipherKey = substr($expanded, 16, 32);
        $macKey = substr($expanded, 48, 32);

        $padded = self::addPadding($plain, 16);
        $ciphertextExpected = openssl_encrypt(
            $padded,
            'aes-256-cbc',
            $cipherKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv,
        );
        self::assertNotFalse($ciphertextExpected);

        $macFull = hash_hmac('sha256', $iv . $ciphertextExpected, $macKey, true);
        $mac10 = substr($macFull, 0, 10);

        self::assertSame($ciphertextExpected . $mac10, $all);
    }

    /**
     * @throws RandomException
     */
    public function testEncryptingStreamGeneratesSidecarWithoutExtraReads(): void
    {
        $mediaKey = random_bytes(32);
        $mediaType = 'IMAGE';

        // >64KB, with a tail to ensure a final partial chunk.
        $plain = random_bytes(65536 + 16 + 123);

        $out = Utils::streamFor('');
        $enc = new EncryptingStream($out, $mediaKey, $mediaType);

        // Write in awkward sizes to exercise buffering.
        $offset = 0;
        foreach ([1, 7, 8191, 3, 65536, 5, 9999] as $len) {
            if ($offset >= strlen($plain)) {
                break;
            }
            $part = substr($plain, $offset, $len);
            $offset += strlen($part);
            $enc->write($part);
        }
        if ($offset < strlen($plain)) {
            $enc->write(substr($plain, $offset));
        }

        $enc->close();

        $expanded = HKDF::expand112ForType($mediaKey, $mediaType);
        $macKey = substr($expanded, 48, 32);

        $sidecarExpected = '';
        $buf = $plain;
        $chunkSize = 65536;
        $overlap = 16;
        $windowLen = $chunkSize + $overlap;

        while (strlen($buf) >= $windowLen) {
            $window = substr($buf, 0, $windowLen);
            $h = hash_hmac('sha256', $window, $macKey, true);
            $sidecarExpected .= substr($h, 0, 10);
            $buf = substr($buf, $chunkSize);
        }
        if ($buf !== '') {
            $h = hash_hmac('sha256', $buf, $macKey, true);
            $sidecarExpected .= substr($h, 0, 10);
        }

        self::assertSame($sidecarExpected, $enc->getSidecar());
    }
}

