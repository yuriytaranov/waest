<?php
declare(strict_types=1);

namespace Waest;

use InvalidArgumentException;
use LogicException;
use Psr\Http\Message\StreamInterface;
use RuntimeException;
use Throwable;

final class DecryptingStream extends EncryptedStreamDecorator
{
    use PaddingTrait;

    private const string CIPHER = 'aes-256-cbc';
    private const int MAC_TRUNCATE_LEN = 10;

    private bool $decrypted = false;

    private string $plaintext = '';
    private int $position = 0;

    public function __construct(StreamInterface $stream, string $mediaKey, string $mediaType)
    {
        parent::__construct($stream, $mediaKey, $mediaType);
    }

    protected function processRead(string $data): string
    {
        throw new LogicException('Use DecryptingStream::read(); incremental decrypt is not supported.');
    }

    protected function processWrite(string $data): string
    {
        throw new LogicException('DecryptingStream is read-only.');
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        throw new RuntimeException('DecryptingStream is read-only.');
    }

    public function read(int $length): string
    {
        if ($length <= 0) {
            return '';
        }

        $this->ensureDecrypted();

        $chunk = substr($this->plaintext, $this->position, $length);
        $this->position += strlen($chunk);

        return $chunk;
    }

    public function getContents(): string
    {
        $this->ensureDecrypted();
        $result = substr($this->plaintext, $this->position);
        $this->position = strlen($this->plaintext);

        return $result;
    }

    public function __toString(): string
    {
        try {
            $this->ensureDecrypted();
            $this->position = 0;
            $out = $this->plaintext;
            $this->position = strlen($this->plaintext);

            return $out;
        } catch (Throwable) {
            return '';
        }
    }

    public function eof(): bool
    {
        $this->ensureDecrypted();

        return $this->position >= strlen($this->plaintext);
    }

    public function tell(): int
    {
        $this->ensureDecrypted();

        return $this->position;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        $this->ensureDecrypted();
        $len = strlen($this->plaintext);

        $newPos = match ($whence) {
            SEEK_SET => $offset,
            SEEK_CUR => $this->position + $offset,
            SEEK_END => $len + $offset,
            default => throw new InvalidArgumentException('Invalid seek whence.'),
        };

        if ($newPos < 0) {
            throw new RuntimeException('Seek before start of stream.');
        }

        $this->position = min($newPos, $len);
    }

    public function rewind(): void
    {
        if ($this->decrypted) {
            $this->position = 0;

            return;
        }

        if ($this->stream->isSeekable()) {
            $this->stream->rewind();
        }

        $this->position = 0;
    }

    public function getSize(): ?int
    {
        if (!$this->decrypted) {
            return null;
        }

        return strlen($this->plaintext);
    }

    private function ensureDecrypted(): void
    {
        if ($this->decrypted) {
            return;
        }

        $payload = $this->readAllFromUnderlying();
        $payloadLen = strlen($payload);
        if ($payloadLen < self::MAC_TRUNCATE_LEN) {
            throw new RuntimeException('Encrypted payload too short.');
        }

        $mac = substr($payload, -self::MAC_TRUNCATE_LEN);
        $cipher = substr($payload, 0, -self::MAC_TRUNCATE_LEN);

        $expectedMac = substr(
            hash_hmac('sha256', $this->iv . $cipher, $this->macKey, true),
            0,
            self::MAC_TRUNCATE_LEN,
        );

        if (!hash_equals($expectedMac, $mac)) {
            throw new RuntimeException('MAC verification failed.');
        }

        $paddedPlain = openssl_decrypt(
            $cipher,
            self::CIPHER,
            $this->cipherKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $this->iv,
        );

        if ($paddedPlain === false) {
            throw new RuntimeException('Decryption failed.');
        }

        $this->plaintext = self::removePadding($paddedPlain, 16);
        $this->decrypted = true;
    }

    private function readAllFromUnderlying(): string
    {
        if ($this->stream->isSeekable()) {
            $this->stream->rewind();
        }

        $buffer = '';
        while (!$this->stream->eof()) {
            $buffer .= $this->stream->read(65536);
        }

        return $buffer;
    }
}
