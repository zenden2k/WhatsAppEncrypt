<?php

namespace Zenden2k\WhatsAppEncrypt;

use LogicException;
use Psr\Http\Message\StreamInterface;

class DecryptStream extends AbstractCryptStream
{
    private ?bool $validated = null;
    private ?int $macPos = null;
    private int $pos = 0;
    private string $plainBuffer = '';
    private string $cipherBuffer = '';

    /**
     * @param StreamInterface $stream
     * @param string $mediaKey
     * @param string $appInfo
     * @throws \Exception
     */
    public function __construct(StreamInterface $stream, string $mediaKey, string $appInfo)
    {
        parent::__construct($stream, $mediaKey, $appInfo);
        $this->validate();
    }

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

        $readBytes = 0;
        $this->macPos = $this->stream->getSize() - self::MAC_SIZE;
        $hashContext = hash_init('sha256', HASH_HMAC, $this->macKey);

        hash_update($hashContext, $this->iv);
        while(!$this->stream->eof()) {
            $bytesToRead = min(
                self::BUFFER_SIZE,
                $this->macPos - $readBytes
            );
            if ($bytesToRead <= 0) {
                break;
            }
            $data = $this->stream->read($bytesToRead);
            $readBytes += strlen($data);
            hash_update($hashContext, $data);
        }

        $calculatedHash = hash_final($hashContext, true);
        $exactHash = $this->stream->read(self::MAC_SIZE);
        $this->stream->rewind();
        if (substr($calculatedHash,0, self::MAC_SIZE) !== $exactHash) {
            throw new DataIntegrityCheckFailedException("MAC check failed. The input stream is corrupted");
        }

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
            return $this->getContents();
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
        return null;
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
        if ($this->macPos === null) {
            return false;
        }
        return $this->cipherBuffer === '' && ($this->macPos - $this->stream->tell() <= 0);
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
        if ($whence === SEEK_CUR) {
            $offset = $this->tell() + $offset;
            $whence = SEEK_SET;
        }

        if ($whence === SEEK_SET) {
            $this->plainBuffer = '';
            $this->cipherBuffer = '';
            $wholeBlockOffset = (int) ($offset / self::BLOCK_SIZE) * self::BLOCK_SIZE;
            $prevBlockOffset = $wholeBlockOffset - self::BLOCK_SIZE;

            if ($prevBlockOffset < 0) {
                $this->iv = $this->baseIv;
                $this->stream->seek(0);
            } else {
                $this->stream->seek($prevBlockOffset);
                $this->iv = $this->stream->read(self::BLOCK_SIZE);
            }
            $this->pos = $wholeBlockOffset;
            $this->read($offset - $wholeBlockOffset);
        } else {
            throw new LogicException('Unrecognized whence.');
        }
    }

    /**
     * @inheritDoc
     */
    public function rewind(): void
    {
        $this->stream->rewind();
        $this->pos = 0;
        $this->iv = $this->baseIv;
        $this->plainBuffer = '';
        $this->cipherBuffer = '';
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
        return $this->stream->isReadable();
    }

    private function decryptBlock(int $length): string
    {
        if ($this->eof()) {
            return '';
        }

        $length = min($length, $this->macPos - $this->stream->tell());

        $cipherText = $this->cipherBuffer;
        while (strlen($cipherText) < $length && !($this->macPos - $this->stream->tell() <= 0)) {
            $cipherText .= $this->stream->read($length - strlen($cipherText));
        }
        $bytesLeft = $this->macPos - $this->stream->tell();
        $blockSize = min(self::BLOCK_SIZE, $bytesLeft);

        $this->cipherBuffer = $this->stream->read($blockSize);

        $options = OPENSSL_RAW_DATA;

        if (!$this->eof()){
            $options |= OPENSSL_NO_PADDING;
        } else {
            $this->stream->read(self::MAC_SIZE);
        }
        $decryptedData = openssl_decrypt($cipherText, 'aes-256-cbc', $this->cipherKey, $options, $this->iv);
        if ($decryptedData === false) {
            throw new DecryptionFailedException("Unable to decrypt. Please ensure you have provided the correct algorithm, initialization vector, and key.");
        }

        $this->pos += strlen($decryptedData);
        $this->iv = substr($cipherText, - self::BLOCK_SIZE);

        return $decryptedData;
    }

    /**
     * @inheritDoc
     */
    public function read(int $length): string
    {
        $this->validate();

        if ($length > strlen($this->plainBuffer)) {
            $this->plainBuffer .= $this->decryptBlock(
                self::BLOCK_SIZE * ceil(($length - strlen($this->plainBuffer)) / self::BLOCK_SIZE)
            );
        }

        $data = substr($this->plainBuffer, 0, $length);
        $this->plainBuffer = substr($this->plainBuffer, $length);

        return $data;
    }

    /**
     * @inheritDoc
     */
    public function getContents(): string
    {
        $this->validate();

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
}