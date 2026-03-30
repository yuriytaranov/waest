<?php
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

if (!class_exists(\GuzzleHttp\Psr7\Utils::class)) {
    fwrite(STDERR, "Нужен guzzlehttp/psr7. Выполните: composer install\n");
    exit(1);
}

use GuzzleHttp\Psr7\Utils;
use Waest\DecryptingStream;
use Waest\HKDF;

/** @var list<string> */
const MEDIA_TYPES = ['IMAGE', 'VIDEO', 'AUDIO', 'DOCUMENT'];

/**
 * @return non-empty-string
 */
function readMediaKey(string $path): string
{
    $raw = @file_get_contents($path);
    if ($raw === false) {
        throw new RuntimeException("Не удалось прочитать ключ: {$path}");
    }

    $trimmed = trim($raw);
    if (strlen($trimmed) === 64 && ctype_xdigit($trimmed)) {
        $bin = hex2bin($trimmed);
        if ($bin === false) {
            throw new InvalidArgumentException("Некорректный hex-ключ: {$path}");
        }
        $raw = $bin;
    }

    if (strlen($raw) !== 32) {
        throw new InvalidArgumentException('mediaKey должен быть ровно 32 байта (или 64 hex-символа): ' . $path);
    }

    return $raw;
}

$rootEncrypt = __DIR__ . '/samples/encrypt';
$rootDecrypt = __DIR__ . '/samples/decrypt';

if (!is_dir($rootEncrypt)) {
    fwrite(STDERR, "Нет каталога: {$rootEncrypt}\n");
    exit(1);
}

if (!is_dir($rootDecrypt) && !@mkdir($rootDecrypt, 0755, true) && !is_dir($rootDecrypt)) {
    fwrite(STDERR, "Не удалось создать: {$rootDecrypt}\n");
    exit(1);
}

$processed = 0;
$exit = 0;

foreach (MEDIA_TYPES as $type) {
    $typeEncryptDir = $rootEncrypt . '/' . $type;
    if (!is_dir($typeEncryptDir)) {
        continue;
    }

    HKDF::infoForType($type);

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($typeEncryptDir, FilesystemIterator::SKIP_DOTS),
    );

    foreach ($iterator as $fileInfo) {
        if (!$fileInfo instanceof SplFileInfo || !$fileInfo->isFile()) {
            continue;
        }

        $srcPath = $fileInfo->getPathname();
        if (!str_ends_with($srcPath, '.encrypted')) {
            continue;
        }

        $stem = $fileInfo->getBasename('.encrypted');
        if ($stem === '') {
            continue;
        }

        $keyPath = $fileInfo->getPath() . '/' . $stem . '.key';
        if (!is_file($keyPath) || !is_readable($keyPath)) {
            fwrite(STDERR, "Нет ключа для {$srcPath}: ожидается {$keyPath}\n");
            $exit = 1;
            continue;
        }

        $rel = substr($srcPath, strlen($typeEncryptDir));
        $rel = str_replace(DIRECTORY_SEPARATOR, '/', $rel);
        $rel = ltrim($rel, '/');
        $parentRel = dirname($rel);

        if ($parentRel === '.' || $parentRel === '') {
            $destDir = "{$rootDecrypt}/{$type}";
        } else {
            $destDir = "{$rootDecrypt}/{$type}/{$parentRel}";
        }

        if (!is_dir($destDir) && !@mkdir($destDir, 0755, true) && !is_dir($destDir)) {
            fwrite(STDERR, "Не удалось создать каталог: {$destDir}\n");
            $exit = 1;
            continue;
        }

        $outPath = "{$destDir}/{$stem}.bin";

        try {
            $mediaKey = readMediaKey($keyPath);
            $cipherBlob = file_get_contents($srcPath);
            if ($cipherBlob === false) {
                throw new RuntimeException("Чтение: {$srcPath}");
            }

            $in = Utils::streamFor($cipherBlob);
            $dec = new DecryptingStream($in, $mediaKey, $type);
            $plain = $dec->getContents();

            if (file_put_contents($outPath, $plain) === false) {
                throw new RuntimeException("Запись: {$outPath}");
            }

            echo "{$srcPath} → {$outPath}\n";
            ++$processed;
        } catch (Throwable $e) {
            fwrite(STDERR, "{$srcPath}: {$e->getMessage()}\n");
            $exit = 1;
        }
    }
}

if ($processed === 0) {
    echo "Файлов .encrypted не найдено. Ожидается структура вроде {$rootEncrypt}/IMAGE/<stem>.encrypted + <stem>.key\n";
}

exit($exit);
