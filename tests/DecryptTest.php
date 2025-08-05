<?php

namespace Zenden2k\WhatsappEncrypt\Tests;

use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;
use Zenden2k\WhatsappEncrypt\DecryptStream;
use Zenden2k\WhatsappEncrypt\Helper;

class DecryptTest extends TestCase
{
    private array $sampleFileCache = [];
    private function getSampleFileContents(string $fileName)
    {
        if (!isset($this->sampleFileCache[$fileName])) {
            $this->sampleFileCache[$fileName] = file_get_contents(SAMPLES_DIR . $fileName);
        }
        return $this->sampleFileCache[$fileName];
    }

    private function doTestReadFile(string $fileName, string $mediaType) {
        $file = Psr7\Utils::streamFor(fopen(SAMPLES_DIR . $fileName . '.encrypted', 'rb'));
        $decryptStream = new DecryptStream($file, $this->getSampleFileContents($fileName.'.key'), $mediaType);
        $this->assertEquals($this->getSampleFileContents( $fileName . '.original'), $decryptStream->getContents());
    }

    private function doTestPartialReadFile(string $fileName, string $mediaType, int $bufferSize = 32 * 1024)
    {
        $imageFile = Psr7\Utils::streamFor(fopen(SAMPLES_DIR . $fileName . '.encrypted', 'r'));
        $decryptStream = new DecryptStream($imageFile, $this->getSampleFileContents($fileName.'.key'), $mediaType);
        $data = '';
        while(!$decryptStream->eof()) {
            $data .= $decryptStream->read($bufferSize);
        }
        file_put_contents(SAMPLES_DIR . '/../'. $fileName . '.original', $data);
        $this->assertEquals($this->getSampleFileContents( $fileName . '.original'), $data);
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
        $this->doTestPartialReadFile('VIDEO', Helper::MEDIA_TYPE_VIDEO, 33337);
        $this->doTestPartialReadFile('AUDIO', Helper::MEDIA_TYPE_AUDIO, 2225);
    }

    private function doTestRewind(string $fileName, string $mediaType) {
        $file = Psr7\Utils::streamFor(fopen(SAMPLES_DIR . $fileName . '.encrypted', 'rb'));
        $decryptStream = new DecryptStream($file, $this->getSampleFileContents($fileName.'.key'), $mediaType);
        $originalFileContents = $this->getSampleFileContents( $fileName . '.original');
        $this->assertEquals($originalFileContents, $decryptStream->getContents());
        $decryptStream->rewind();
        $this->assertEquals($originalFileContents, $decryptStream->getContents());
    }

    private function doTestSeek(string $fileName, string $mediaType) {
        $file = Psr7\Utils::streamFor(fopen(SAMPLES_DIR . $fileName . '.encrypted', 'rb'));
        $decryptStream = new DecryptStream($file, $this->getSampleFileContents($fileName.'.key'), $mediaType);
        $originalFileContents = $this->getSampleFileContents( $fileName . '.original');
        $this->assertEquals($originalFileContents, $decryptStream->getContents());
        $decryptStream->seek(0);
        $this->assertEquals($originalFileContents, $decryptStream->getContents());
    }
    public function testRewind()
    {
        $this->doTestRewind('IMAGE', Helper::MEDIA_TYPE_IMAGE);
        $this->doTestRewind('VIDEO', Helper::MEDIA_TYPE_VIDEO);
        $this->doTestRewind('AUDIO', Helper::MEDIA_TYPE_AUDIO);
    }

    public function testSeek()
    {
        $this->doTestRewind('IMAGE', Helper::MEDIA_TYPE_IMAGE);
        $this->doTestRewind('VIDEO', Helper::MEDIA_TYPE_VIDEO);
        $this->doTestRewind('AUDIO', Helper::MEDIA_TYPE_AUDIO);
    }

    public function testSeekThrowsException() {
        $fileName = 'IMAGE';
        $mediaType = Helper::MEDIA_TYPE_IMAGE;
        $this->expectException(\LogicException::class);
        $file = Psr7\Utils::streamFor(fopen(SAMPLES_DIR . $fileName . '.encrypted', 'rb'));
        $decryptStream = new DecryptStream($file, $this->getSampleFileContents($fileName.'.key'), $mediaType);
        $originalFileContents = $this->getSampleFileContents( $fileName . '.original');
        $this->assertEquals($originalFileContents, $decryptStream->getContents());
        $decryptStream->seek(5555);
        $this->assertEquals($originalFileContents, $decryptStream->getContents());
    }

    private function doTestToString(string $fileName, string $mediaType) {
        $file = Psr7\Utils::streamFor(fopen(SAMPLES_DIR . $fileName . '.encrypted', 'rb'));
        $decryptStream = new DecryptStream($file, $this->getSampleFileContents($fileName.'.key'), $mediaType);
        $this->assertEquals($this->getSampleFileContents( $fileName . '.original'), (string)$decryptStream);
    }

    public function testToString()
    {
        $this->doTestToString('IMAGE', Helper::MEDIA_TYPE_IMAGE);
        $this->doTestToString('VIDEO', Helper::MEDIA_TYPE_VIDEO);
        $this->doTestToString('AUDIO', Helper::MEDIA_TYPE_AUDIO);
    }

    private function doTestToStringRewind(string $fileName, string $mediaType) {
        $file = Psr7\Utils::streamFor(fopen(SAMPLES_DIR . $fileName . '.encrypted', 'rb'));
        $decryptStream = new DecryptStream($file, $this->getSampleFileContents($fileName.'.key'), $mediaType);
        $decryptStream->read(1024);
        $this->assertEquals($this->getSampleFileContents( $fileName . '.original'), (string)$decryptStream);
    }
    public function testToStringRewind()
    {
        $this->doTestToStringRewind('IMAGE', Helper::MEDIA_TYPE_IMAGE);
        $this->doTestToStringRewind('VIDEO', Helper::MEDIA_TYPE_VIDEO);
        $this->doTestToStringRewind('AUDIO', Helper::MEDIA_TYPE_AUDIO);
    }
}