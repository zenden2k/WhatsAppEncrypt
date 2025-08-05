<?php

namespace Zenden2k\WhatsappEncrypt\Tests;

trait SampleFileTrait
{
    private array $sampleFileCache = [];
    private function getSampleFileContents(string $fileName)
    {
        if (!isset($this->sampleFileCache[$fileName])) {
            $this->sampleFileCache[$fileName] = file_get_contents(SAMPLES_DIR . $fileName);
        }
        return $this->sampleFileCache[$fileName];
    }

}