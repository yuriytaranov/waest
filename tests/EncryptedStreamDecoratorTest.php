<?php
declare(strict_types=1);

namespace Waest\Tests;

use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use RuntimeException;
use Waest\EncryptedStreamDecorator;

final class EncryptedStreamDecoratorTest extends TestCase
{
    /**
     * @throws RandomException
     */
    public function testReadGetContentsAndToStringApplyProcessReadUsingGuzzleStream(): void
    {
        $inner = Utils::streamFor('abcDEF');
        $mediaKey = random_bytes(32);

        $decorated = new class($inner, $mediaKey, 'IMAGE') extends EncryptedStreamDecorator {
            protected function processRead(string $data): string
            {
                return strtoupper($data);
            }

            protected function processWrite(string $data): string
            {
                return $data;
            }
        };

        $decorated->rewind();
        self::assertSame('ABCDEF', $decorated->read(6));

        $decorated->rewind();
        self::assertSame('ABCDEF', $decorated->getContents());

        $decorated->rewind();
        self::assertSame('ABCDEF', (string) $decorated);
    }

    /**
     * @throws RandomException
     */
    public function testWriteAppliesProcessWriteUsingPhpMemoryStream(): void
    {
        $h = fopen('php://memory', 'w+');
        self::assertNotFalse($h);

        $inner = Utils::streamFor($h);
        $mediaKey = random_bytes(32);

        $decorated = new class($inner, $mediaKey, 'IMAGE') extends EncryptedStreamDecorator {
            protected function processRead(string $data): string
            {
                return $data;
            }

            protected function processWrite(string $data): string
            {
                return '[' . $data . ']';
            }
        };

        $written = $decorated->write('hi');
        // Base decorator returns bytes written to the underlying stream (after transformation).
        self::assertSame(4, $written); // "[hi]"

        $inner->rewind();
        self::assertSame('[hi]', $inner->getContents());
    }

    /**
     * @throws RandomException
     */
    public function testToStringReturnsEmptyStringIfProcessReadThrows(): void
    {
        $inner = Utils::streamFor('boom');
        $mediaKey = random_bytes(32);

        $decorated = new class($inner, $mediaKey, 'IMAGE') extends EncryptedStreamDecorator {
            protected function processRead(string $data): string
            {
                throw new RuntimeException('nope');
            }

            protected function processWrite(string $data): string
            {
                return $data;
            }
        };

        self::assertSame('', (string) $decorated);
    }
}

