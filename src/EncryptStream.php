<?php

namespace Zenden2k\WhatsAppEncrypt;

use Psr\Http\Message\StreamInterface;


class EncryptStream extends AbstractCryptStream
{
    const SIDECAR_CHUNK_SIZE = 64 * 1024;
    private \HashContext $hashContext;
    private string $buffer = '';
    private int $pos = 0;
    private int $macPos;
    private ?string $hash = null;
    private string $sidecarBuffer = '';
    private ?StreamInterface $sidecarStream;

    public function __construct(StreamInterface $stream, string $mediaKey, string $appInfo, ?StreamInterface $sidecarStream = null)
    {
        parent::__construct($stream, $mediaKey, $appInfo);

        $this->macPos = $this->getSize() - self::MAC_SIZE;
        $this->sidecarStream = $sidecarStream;
        $this->initHash();
    }

    private function initHash()
    {
        $this->hashContext = hash_init('sha256', HASH_HMAC, $this->macKey);
        hash_update($this->hashContext, $this->iv);
    }

    /**
     * @inheritDoc
     */
    public function __toString(): string
    {
        try {
            $this->rewind();
            return $this->read($this->getSize());
        } catch (\Throwable $exception) {
            return '';
        }
    }

    /**
     * @inheritDoc
     */
    public function close(): void
    {
        $this->stream->close();
    }

    /**
     * @inheritDoc
     */
    public function detach()
    {
        $this->stream->detach();
    }

    /**
     * @inheritDoc
     */
    public function getSize(): ?int
    {
        $len = $this->stream->getSize();
        $padding = self::BLOCK_SIZE - $len % self::BLOCK_SIZE;
        return $len + $padding + self::MAC_SIZE;
    }

    /**
     * @inheritDoc
     */
    public function tell(): int
    {
        return $this->pos;
    }

    /**
     * @inheritDoc
     */
    public function eof(): bool
    {
        return $this->pos >= $this->getSize();
    }

    /**
     * @inheritDoc
     */
    public function isSeekable(): bool
    {
        return $this->stream->isSeekable();
    }

    /**
     * @inheritDoc
     */
    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        if ($offset === 0 && $whence === SEEK_SET) {
            $this->stream->seek(0);
            $this->buffer = '';
            $this->pos = $offset;
            $this->iv = $this->baseIv;
            $this->initHash();
        } else {
            throw new \LogicException('Encryption streams only support being rewound, not arbitrary seeking.');
        }
    }

    /**
     * @inheritDoc
     */
    public function rewind(): void
    {
        $this->stream->rewind();
        $this->pos = 0;
        $this->buffer = '';
        $this->iv = $this->baseIv;
        $this->initHash();
    }

    /**
     * @inheritDoc
     */
    public function isWritable(): bool
    {
        return false;
    }


    /**
     * @inheritDoc
     */
    public function write(string $string): int
    {
        throw new \LogicException('Decryption streams are not writable');
    }

    /**
     * @inheritDoc
     */
    public function isReadable(): bool
    {
        return $this->stream->isReadable();
    }

    private function encryptBlock(int $length): string
    {
        if ($this->stream->eof()) {
            return '';
        }

        $plainText = '';
        do {
            $plainText .= $this->stream->read($length - strlen($plainText));
        } while (strlen($plainText) < $length && !$this->stream->eof());

        $options = OPENSSL_RAW_DATA;
        if (!$this->stream->eof()) {
            $options |= OPENSSL_ZERO_PADDING;
        }

        $cipherText = openssl_encrypt(
            $plainText,
            'aes-256-cbc',
            $this->cipherKey,
            $options,
            $this->iv
        );

        if ($cipherText === false) {
            throw new EncryptionFailedException("Unable to encrypt data. Please ensure you have provided a valid algorithm and initialization vector.");
        }

        if ($this->hash === null) {
            hash_update($this->hashContext, $cipherText);
            if ($this->stream->eof()) {
                $this->hash = substr(hash_final($this->hashContext, true), 0, self::MAC_SIZE);
            }
        }

        $this->iv = substr($cipherText, self::BLOCK_SIZE * -1);

        return $cipherText;
    }

    /**
     * @inheritDoc
     */
    public function read(int $length): string
    {
        if ($length > strlen($this->buffer)) {
            $this->buffer .= $this->encryptBlock(
                self::BLOCK_SIZE * ceil(($length - strlen($this->buffer)) / self::BLOCK_SIZE)
            );
        }

        $data = substr($this->buffer, 0, $length);

        $this->pos += strlen($data);

        if ($this->sidecarStream !== null) {
            $this->sidecarBuffer .= $data;
            $this->generateSidecar($this->stream->eof());
        }

        if ($this->pos >= $this->macPos) {
            $leftBytesCount = max(0, $length - strlen($data));
            $hashPart = substr($this->hash, $this->pos - $this->macPos, $leftBytesCount);
            $data .= $hashPart;
            $this->pos  += strlen($hashPart);
        }

        $this->buffer = substr($this->buffer, $length);

        return $data;
    }

    /**
     * @inheritDoc
     */
    public function getContents(): string
    {
        $result = '';
        while (!$this->eof()) {
            $result .= $this->read(self::BUFFER_SIZE);
        }

        return $result;
    }

    /**
     * @inheritDoc
     */
    public function getMetadata(?string $key = null)
    {
        return $this->stream->getMetadata($key);
    }

    private function generateSidecar(bool $finish = false)
    {
        $len = strlen($this->sidecarBuffer);

        if (!$len) {
            return;
        }

        for ($offset = 0; $offset < $len; $offset += self::SIDECAR_CHUNK_SIZE) {
            if (!$finish && ($len - $offset < self::SIDECAR_CHUNK_SIZE + 16)) {
                break;
            }

            $hashContext = hash_init('sha256', HASH_HMAC, $this->macKey);
            hash_update($hashContext, substr($this->sidecarBuffer, $offset, self::SIDECAR_CHUNK_SIZE + 16));

            $this->sidecarStream->write(substr(hash_final($hashContext, true), 0, self::MAC_SIZE));
        }
        $this->sidecarBuffer = substr($this->sidecarBuffer, $offset);
    }
}