<?php
declare(strict_types=1);

namespace Waest;

use LogicException;
use Psr\Http\Message\StreamInterface;
use RuntimeException;

final class EncryptingStream extends EncryptedStreamDecorator
{
    use PaddingTrait;

    private const int BLOCK_SIZE = 16;
    private const int SIDECAR_CHUNK_SIZE = 65536; // 64KB
    private const int SIDECAR_OVERLAP = 16;
    private const string CIPHER = 'aes-256-cbc';
    private const int MAC_TRUNCATE_LEN = 10;

    private string $plainBuffer = '';
    private string $currentIv;

    /** @var resource|null */
    private $hmacCtx;

    private bool $macAppended = false;

    /**
     * Plaintext buffer used to generate the per-chunk sidecar MACs.
     * The algorithm emits one entry when we have (64KB + 16) bytes available,
     * then advances by 64KB (keeping 16 bytes overlap).
     */
    private string $sidecarPlainBuffer = '';
    private string $sidecar = '';

    public function __construct(StreamInterface $stream, string $mediaKey, string $mediaType)
    {
        parent::__construct($stream, $mediaKey, $mediaType);

        $this->currentIv = $this->iv;
        $this->hmacCtx = hash_init('sha256', HASH_HMAC, $this->macKey);
        hash_update($this->hmacCtx, $this->iv);
    }

    /**
     * Returns the generated sidecar bytes (concatenated 10-byte MAC prefixes).
     * Safe to call at any time; the sidecar is finalized in close().
     */
    public function getSidecar(): string
    {
        return $this->sidecar;
    }

    protected function processRead(string $data): string
    {
        // In encryption mode, reading doesn't transform bytes.
        return $data;
    }

    /**
     * Accumulates plaintext, encrypts only full blocks.
     * Final padding + encryption happen in close().
     */
    protected function processWrite(string $data): string
    {
        if ($data === '') {
            return '';
        }

        $this->plainBuffer .= $data;

        $fullLen = intdiv(strlen($this->plainBuffer), self::BLOCK_SIZE) * self::BLOCK_SIZE;
        if ($fullLen === 0) {
            return '';
        }

        $toEncrypt = substr($this->plainBuffer, 0, $fullLen);
        $this->plainBuffer = substr($this->plainBuffer, $fullLen);

        return $this->encryptRawNoPadding($toEncrypt);
    }

    public function write(string $string): int
    {
        if ($string === '') {
            return 0;
        }

        if (!$this->isWritable()) {
            throw new RuntimeException('Underlying stream is not writable.');
        }

        $this->updateSidecar($string);

        $ciphertext = $this->processWrite($string);
        if ($ciphertext !== '') {
            $written = $this->stream->write($ciphertext);
            if ($written !== strlen($ciphertext)) {
                throw new RuntimeException('Failed to write encrypted bytes to underlying stream.');
            }
        }

        // Bytes accepted from caller (plaintext length).
        return strlen($string);
    }

    public function close(): void
    {
        if ($this->macAppended) {
            return;
        }

        if ($this->isWritable()) {
            $this->finalizeSidecar();

            // Always add PKCS#7 padding, even if buffer is empty.
            $finalPlain = self::addPadding($this->plainBuffer, self::BLOCK_SIZE);
            $this->plainBuffer = '';

            $finalCipher = $this->encryptRawNoPadding($finalPlain);
            if ($finalCipher !== '') {
                $written = $this->stream->write($finalCipher);
                if ($written !== strlen($finalCipher)) {
                    throw new RuntimeException('Failed to write final encrypted bytes to underlying stream.');
                }
            }

            $macFull = hash_final($this->hmacCtx, true);
            $mac10 = substr($macFull, 0, self::MAC_TRUNCATE_LEN);

            $writtenMac = $this->stream->write($mac10);
            if ($writtenMac !== strlen($mac10)) {
                throw new RuntimeException('Failed to write MAC to underlying stream.');
            }
        }

        $this->macAppended = true;
    }

    private function updateSidecar(string $plain): void
    {
        $this->sidecarPlainBuffer .= $plain;

        $windowLen = self::SIDECAR_CHUNK_SIZE + self::SIDECAR_OVERLAP;
        while (strlen($this->sidecarPlainBuffer) >= $windowLen) {
            $window = substr($this->sidecarPlainBuffer, 0, $windowLen);
            $this->sidecar .= $this->hmac10($window);

            // Advance by 64KB, keeping the 16-byte overlap in the buffer.
            $this->sidecarPlainBuffer = substr($this->sidecarPlainBuffer, self::SIDECAR_CHUNK_SIZE);
        }
    }

    private function finalizeSidecar(): void
    {
        // Emit the last chunk (possibly shorter than 64KB+16).
        if ($this->sidecarPlainBuffer !== '') {
            $this->sidecar .= $this->hmac10($this->sidecarPlainBuffer);
            $this->sidecarPlainBuffer = '';
        }
    }

    private function hmac10(string $data): string
    {
        $full = hash_hmac('sha256', $data, $this->macKey, true);
        return substr($full, 0, self::MAC_TRUNCATE_LEN);
    }

    private function encryptRawNoPadding(string $plain): string
    {
        if ($plain === '') {
            return '';
        }

        if ((strlen($plain) % self::BLOCK_SIZE) !== 0) {
            throw new LogicException('Plaintext must be block-aligned for raw CBC encryption.');
        }

        $ciphertext = openssl_encrypt(
            $plain,
            self::CIPHER,
            $this->cipherKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $this->currentIv,
        );

        if ($ciphertext === false) {
            throw new RuntimeException('openssl_encrypt failed.');
        }

        hash_update($this->hmacCtx, $ciphertext);

        $this->currentIv = substr($ciphertext, -self::BLOCK_SIZE);

        return $ciphertext;
    }
}

