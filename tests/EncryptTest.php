<?php

namespace Zenden2k\WhatsAppEncrypt\Tests;

use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;
use Zenden2k\WhatsAppEncrypt\EncryptStream;
use Zenden2k\WhatsAppEncrypt\Helper;

class EncryptTest extends TestCase
{
    use SampleFileTrait;

    private function doTestReadFile(string $fileName, string $mediaType): EncryptStream {
        $file = Psr7\Utils::streamFor(fopen(SAMPLES_DIR . $fileName . '.original', 'rb'));
        $encryptStream = new EncryptStream($file, $this->getSampleFileContents($fileName.'.key'), $mediaType);
        $this->assertEquals($this->getSampleFileContents( $fileName . '.encrypted'), $encryptStream->getContents());
        return $encryptStream;
    }

    private function doTestPartialReadFile(string $fileName, string $mediaType, int $bufferSize = 32 * 1024,
                                           ?StreamInterface $sidecarStream = null): EncryptStream
    {
        $imageFile = Psr7\Utils::streamFor(fopen(SAMPLES_DIR . $fileName . '.original', 'r'));
        $encryptStream = new EncryptStream($imageFile, $this->getSampleFileContents($fileName.'.key'), $mediaType, $sidecarStream);
        $data = '';

        while(!$encryptStream->eof()) {
            $data .= $encryptStream->read($bufferSize);
        }

        $this->assertEquals($this->getSampleFileContents( $fileName . '.encrypted'), $data);
        return $encryptStream;
    }

    public function testReadFiles()
    {
        $this->doTestReadFile('IMAGE', Helper::MEDIA_TYPE_IMAGE);
        $this->doTestReadFile('VIDEO', Helper::MEDIA_TYPE_VIDEO);
        $this->doTestReadFile('AUDIO', Helper::MEDIA_TYPE_AUDIO);
    }

    public function testPartialReadFiles()
    {
        $this->doTestPartialReadFile('IMAGE', Helper::MEDIA_TYPE_IMAGE);
        $this->doTestPartialReadFile('VIDEO', Helper::MEDIA_TYPE_VIDEO);
        $this->doTestPartialReadFile('AUDIO', Helper::MEDIA_TYPE_AUDIO);
    }

    public function testPartialReadNotMultipleBufferSize()
    {
        $this->doTestPartialReadFile('IMAGE', Helper::MEDIA_TYPE_IMAGE,1111);
        $this->doTestPartialReadFile('IMAGE', Helper::MEDIA_TYPE_IMAGE,7);
        $this->doTestPartialReadFile('VIDEO', Helper::MEDIA_TYPE_VIDEO, 33337);
        $this->doTestPartialReadFile('AUDIO', Helper::MEDIA_TYPE_AUDIO, 2225);
    }

    private function doTestRewind(string $fileName, string $mediaType) {
        $file = Psr7\Utils::streamFor(fopen(SAMPLES_DIR . $fileName . '.original', 'rb'));
        $encryptStream = new EncryptStream($file, $this->getSampleFileContents($fileName.'.key'), $mediaType);
        $originalFileContents = $this->getSampleFileContents( $fileName . '.encrypted');
        $this->assertEquals($originalFileContents, $encryptStream->getContents());
        $encryptStream->rewind();
        $this->assertEquals($originalFileContents, $encryptStream->getContents());
    }

    public function testRewind()
    {
        $this->doTestRewind('IMAGE', Helper::MEDIA_TYPE_IMAGE);
        $this->doTestRewind('VIDEO', Helper::MEDIA_TYPE_VIDEO);
        $this->doTestRewind('AUDIO', Helper::MEDIA_TYPE_AUDIO);
    }

    private function doTestSeek(string $fileName, string $mediaType) {
        $file = Psr7\Utils::streamFor(fopen(SAMPLES_DIR . $fileName . '.original', 'rb'));
        $encryptStream = new EncryptStream($file, $this->getSampleFileContents($fileName.'.key'), $mediaType);
        $originalFileContents = $this->getSampleFileContents( $fileName . '.encrypted');
        $this->assertEquals($originalFileContents, $encryptStream->getContents());
        $encryptStream->seek(0);
        $this->assertEquals($originalFileContents, $encryptStream->getContents());
    }

    public function testSeek()
    {
        $this->doTestSeek('IMAGE', Helper::MEDIA_TYPE_IMAGE);
        $this->doTestSeek('VIDEO', Helper::MEDIA_TYPE_VIDEO);
        $this->doTestSeek('AUDIO', Helper::MEDIA_TYPE_AUDIO);
    }

    public function testSeekThrowsException() {
        $fileName = 'IMAGE';
        $mediaType = Helper::MEDIA_TYPE_IMAGE;
        $this->expectException(\LogicException::class);
        $file = Psr7\Utils::streamFor(fopen(SAMPLES_DIR . $fileName . '.original', 'rb'));
        $decryptStream = new EncryptStream($file, $this->getSampleFileContents($fileName.'.key'), $mediaType);
        $originalFileContents = $this->getSampleFileContents( $fileName . '.encrypted');
        $this->assertEquals($originalFileContents, $decryptStream->getContents());
        $decryptStream->seek(5555);
        $this->assertEquals($originalFileContents, $decryptStream->getContents());
    }

    private function doTestToString(string $fileName, string $mediaType) {
        $file = Psr7\Utils::streamFor(fopen(SAMPLES_DIR . $fileName . '.original', 'rb'));
        $encryptStream = new EncryptStream($file, $this->getSampleFileContents($fileName.'.key'), $mediaType);
        $this->assertEquals($this->getSampleFileContents( $fileName . '.encrypted'), (string)$encryptStream);
    }

    public function testToString()
    {
        $this->doTestToString('IMAGE', Helper::MEDIA_TYPE_IMAGE);
        $this->doTestToString('VIDEO', Helper::MEDIA_TYPE_VIDEO);
        $this->doTestToString('AUDIO', Helper::MEDIA_TYPE_AUDIO);
    }

    private function doTestToStringRewind(string $fileName, string $mediaType) {
        $file = Psr7\Utils::streamFor(fopen(SAMPLES_DIR . $fileName . '.original', 'rb'));
        $encryptStream = new EncryptStream($file, $this->getSampleFileContents($fileName.'.key'), $mediaType);
        $encryptStream->read(1024);
        $this->assertEquals($this->getSampleFileContents( $fileName . '.encrypted'), (string)$encryptStream);
    }

    public function testToStringRewind()
    {
        $this->doTestToStringRewind('IMAGE', Helper::MEDIA_TYPE_IMAGE);
        $this->doTestToStringRewind('VIDEO', Helper::MEDIA_TYPE_VIDEO);
        $this->doTestToStringRewind('AUDIO', Helper::MEDIA_TYPE_AUDIO);
    }

    public function testSidecar()
    {
        $this->markTestSkipped();
        $sidecarStream = Psr7\Utils::streamFor(fopen('php://memory', 'r+'));
        $this->doTestPartialReadFile('VIDEO', Helper::MEDIA_TYPE_VIDEO, 32 * 1024, $sidecarStream);
        $this->assertEquals($this->getSampleFileContents('VIDEO.sidecar'), (string)$sidecarStream);
    }
}