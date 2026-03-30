<?php
declare(strict_types=1);

namespace Waest;

use InvalidArgumentException;
use Psr\Http\Message\StreamInterface;
use Throwable;

abstract class EncryptedStreamDecorator implements StreamInterface
{
    protected StreamInterface $stream;
    protected string $mediaKey;
    protected string $mediaType;

    /**
     * 112-byte HKDF output (per WhatsApp media scheme).
     */
    protected string $mediaKeyExpanded;

    /**
     * 32-byte AES key.
     */
    protected string $cipherKey;

    /**
     * 16-byte IV.
     */
    protected string $iv;

    /**
     * 32-byte HMAC key.
     */
    protected string $macKey;

    public function __construct(StreamInterface $stream, string $mediaKey, string $mediaType)
    {
        if (strlen($mediaKey) !== 32) {
            throw new InvalidArgumentException('mediaKey must be exactly 32 bytes.');
        }

        $this->stream = $stream;
        $this->mediaKey = $mediaKey;
        $this->mediaType = $mediaType;

        $this->mediaKeyExpanded = HKDF::expand112ForType($this->mediaKey, $this->mediaType);

        $this->iv = substr($this->mediaKeyExpanded, 0, 16);
        $this->cipherKey = substr($this->mediaKeyExpanded, 16, 32);
        $this->macKey = substr($this->mediaKeyExpanded, 48, 32);
    }

    abstract protected function processRead(string $data): string;

    abstract protected function processWrite(string $data): string;

    public function __toString(): string
    {
        try {
            return $this->processRead($this->stream->__toString());
        } catch (Throwable) {
            return '';
        }
    }

    public function close(): void
    {
        $this->stream->close();
    }

    public function detach()
    {
        return $this->stream->detach();
    }

    public function getSize(): ?int
    {
        return $this->stream->getSize();
    }

    public function tell(): int
    {
        return $this->stream->tell();
    }

    public function eof(): bool
    {
        return $this->stream->eof();
    }

    public function isSeekable(): bool
    {
        return $this->stream->isSeekable();
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        $this->stream->seek($offset, $whence);
    }

    public function rewind(): void
    {
        $this->stream->rewind();
    }

    public function isWritable(): bool
    {
        return $this->stream->isWritable();
    }

    public function write(string $string): int
    {
        $processed = $this->processWrite($string);
        return $this->stream->write($processed);
    }

    public function isReadable(): bool
    {
        return $this->stream->isReadable();
    }

    public function read(int $length): string
    {
        if ($length <= 0) {
            return '';
        }

        $data = $this->stream->read($length);
        if ($data === '') {
            return '';
        }

        return $this->processRead($data);
    }

    public function getContents(): string
    {
        $data = $this->stream->getContents();
        if ($data === '') {
            return '';
        }

        return $this->processRead($data);
    }

    public function getMetadata(?string $key = null)
    {
        return $this->stream->getMetadata($key);
    }
}

