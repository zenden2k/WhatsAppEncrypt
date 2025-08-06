<?php

namespace Zenden2k\WhatsAppEncrypt;

use Psr\Http\Message\StreamInterface;
abstract class AbstractCryptStream implements StreamInterface
{
    protected const BLOCK_SIZE = 16; // 128 bits
    protected const MAC_SIZE = 10;
    protected const BUFFER_SIZE = 32768;
    protected StreamInterface $stream;
    protected string $mediaKey;
    protected string $baseIv;
    protected string $iv;
    protected string $cipherKey;
    protected string $macKey;
    protected string $refKey;

    public function __construct(StreamInterface $stream, string $mediaKey, string $appInfo)
    {
        $this->stream = $stream;
        $this->mediaKey = $mediaKey;
        $mediaKeyExpanded = hash_hkdf('sha256', $mediaKey, 112, $appInfo);
        $this->iv = $this->baseIv = substr($mediaKeyExpanded, 0, 16);
        $this->cipherKey = substr($mediaKeyExpanded, 16, 32);
        $this->macKey = substr($mediaKeyExpanded, 48, 32);
        $this->refKey = substr($mediaKeyExpanded, 80);
    }
}