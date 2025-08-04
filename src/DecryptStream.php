<?php

namespace Zenden2k\WhatsappEncrypt;

use LogicException;

class DecryptStream extends AbstractCryptStream
{
    private const BUFFER_SIZE = 32768;
    private const MAC_TRUNCATION_SIZE = 10;
    private ?bool $validated = null;
    private ?int $length = null;

    private int $pos = 0;

    private string $extraData = '';
    /**
     * @throws \Exception
     */
    private function validate(): void
    {
        if ($this->validated === true) {
            return;
        } else if ($this->validated === false) {
            throw new LogicException('Decrypt stream is not valid');
        }

        $streamLength = $this->stream->getSize();
        $readBytes = 0;
        $hashContext = hash_init('sha256', HASH_HMAC, $this->macKey);
        hash_update($hashContext, $this->iv);
        while(!$this->stream->eof()) {
            $bytesToRead = min(
                self::BUFFER_SIZE,
                $streamLength - $readBytes - self::MAC_TRUNCATION_SIZE
            );
            if ($bytesToRead <= 0) {
                break;
            }
            $data = $this->stream->read($bytesToRead);
            $readBytes += strlen($data);
            hash_update($hashContext, $data);
        }

        $calculatedHash = hash_final($hashContext, true);
        $exactHash = $this->stream->read(self::MAC_TRUNCATION_SIZE);
        $this->stream->rewind();
        if (substr($calculatedHash,0, self::MAC_TRUNCATION_SIZE) !== $exactHash) {
            throw new \Exception("MAC check failed. The input stream is corrupted");
        }
        $this->length = $readBytes;
        $this->validated = true;
    }

    /**
     * @inheritDoc
     */
    public function __toString(): string
    {
        try {
            $this->rewind();
            $this->validate();
            return $this->read($this->length);
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
        return $this->length;
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
        return $this->extraData === '' && $this->stream->eof();
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
            $this->stream->seek(0, SEEK_SET);
            $this->pos = 0;
        } else {
            throw new LogicException('Decryption streams only support being rewound, not arbitrary seeking.');
        }
    }

    /**
     * @inheritDoc
     */
    public function rewind(): void
    {
        $this->stream->rewind();
        $this->pos = 0;
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
        throw new LogicException('Decryption streams are not writable');
    }

    /**
     * @inheritDoc
     */
    public function isReadable(): bool
    {
        $this->stream->isReadable();
    }

    /**
     * @inheritDoc
     */
    public function read(int $length): string
    {
        $this->validate();
        $length = min($length, $this->length - $this->pos - self::MAC_TRUNCATION_SIZE);
        if (!$length) {
            return '';
        }
        $extraDataLen = strlen($this->extraData);

        if ($extraDataLen >= $length) {
            $result = substr($this->extraData, 0, $length);
            $this->extraData = substr($this->extraData, $extraDataLen - $length);
            return $result;
        }
        $bytesNeededCount = $length - $extraDataLen;
        $bytesToReadCount = ($bytesNeededCount + 15) & ~15;
        $data = $this->stream->read($bytesToReadCount);
        $actualReadBytesCount = strlen($data);
        if ($actualReadBytesCount != $bytesToReadCount) {
            throw new \RuntimeException('Original input stream read failed');
        }
        $decryptedData = openssl_decrypt($data, 'aes-256-cbc', $this->cipherKey, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->iv);
        if ($decryptedData === false) {
            throw new \RuntimeException("Decryption stream failed while decrypting data");
        }
        $this->pos += strlen($decryptedData);
        $result = $this->extraData . substr($decryptedData, 0, $bytesNeededCount);
        $this->extraData .= substr($decryptedData, $bytesNeededCount);
        return $result;
    }

    /**
     * @inheritDoc
     */
    public function getContents(): string
    {
        $this->validate();

        return $this->read($this->length - $this->pos);
    }

    /**
     * @inheritDoc
     */
    public function getMetadata(?string $key = null)
    {
        // TODO: Implement getMetadata() method.
    }
}