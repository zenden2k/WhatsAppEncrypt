<?php

namespace Zenden2k\WhatsappEncrypt\Tests;

use PHPUnit\Framework\TestCase;
use Zenden2k\WhatsappEncrypt\DecryptStream;
use GuzzleHttp\Psr7;
use Zenden2k\WhatsappEncrypt\Helper;

class DecryptTest extends TestCase
{
    private function getSampleFileContents(string $fileName)
    {
        return file_get_contents(SAMPLES_DIR . $fileName);
    }

    private function doTestReadFile(string $fileName, string $mediaType) {
        $imageFile = Psr7\Utils::streamFor(fopen(SAMPLES_DIR . $fileName . '.encrypted', 'r'));
        $decryptStream = new DecryptStream($imageFile, $this->getSampleFileContents($fileName.'.key'), $mediaType);
        $this->assertEquals($this->getSampleFileContents( $fileName . '.original'), $decryptStream->getContents());
    }

    public function testReadImage()
    {
        $this->doTestReadFile('IMAGE', Helper::MEDIA_TYPE_IMAGE);
        $this->doTestReadFile('VIDEO', Helper::MEDIA_TYPE_VIDEO);
        $this->doTestReadFile('AUDIO', Helper::MEDIA_TYPE_AUDIO);
    }
}