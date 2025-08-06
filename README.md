# Тестовое задание PHP (WhatsApp encryption decorators for PSR-7 streams)

## Использование пакета

```bash
composer require zenden2k/whatsapp-encrypt
```

Для работы примеров дополнительно нужно установить:

```
composer require guzzlehttp/psr7
```

### Дешифрование

```php
use Zenden2k\WhatsAppEncrypt\DecryptStream;
use Zenden2k\WhatsAppEncrypt\Helper;
use GuzzleHttp\Psr7\Utils;

$file = Utils::streamFor(fopen('samples/IMAGE.encrypted', 'rb'));
$decryptStream = new DecryptStream($file, file_get_contents('samples/IMAGE.key'), Helper::MEDIA_TYPE_IMAGE);
file_put_contents('output/IMAGE.original', $decryptStream->getContents());
```

### Шифрование

```php
use Zenden2k\WhatsAppEncrypt\EncryptStream;
use Zenden2k\WhatsAppEncrypt\Helper;
use GuzzleHttp\Psr7\Utils;

$file = Utils::streamFor(fopen('samples/VIDEO.original', 'rb'));
$sidecarStream = Utils::streamFor(fopen('output/VIDEO.sidecar', 'wb'));
$encryptStream = new EncryptStream($file, file_get_contents('samples/VIDEO.key'), Helper::MEDIA_TYPE_VIDEO, $sidecarStream);
file_put_contents('output/VIDEO.encrypted', $encryptStream->getContents());
```

К сожалению, генерация информации для стриминга (sidecar) дает результат, не совпадающий с эталоном.
