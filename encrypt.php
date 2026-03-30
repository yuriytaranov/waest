<?php
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

if (!class_exists(\GuzzleHttp\Psr7\Utils::class)) {
    fwrite(STDERR, "Нужен guzzlehttp/psr7. Выполните: composer install\n");
    exit(1);
}

use GuzzleHttp\Psr7\Utils;
use Waest\EncryptingStream;
use Waest\HKDF;

/** @var list<string> */
const MEDIA_TYPES = ['IMAGE', 'VIDEO', 'AUDIO', 'DOCUMENT'];

$rootOriginal = __DIR__ . '/samples/original';
$rootEncrypt = __DIR__ . '/samples/encrypt';

if (!is_dir($rootOriginal)) {
    fwrite(STDERR, "Нет каталога: {$rootOriginal}\n");
    exit(1);
}

if (!is_dir($rootEncrypt) && !@mkdir($rootEncrypt, 0755, true) && !is_dir($rootEncrypt)) {
    fwrite(STDERR, "Не удалось создать: {$rootEncrypt}\n");
    exit(1);
}

$processed = 0;
$exit = 0;

foreach (MEDIA_TYPES as $type) {
    $typeDir = $rootOriginal . '/' . $type;
    if (!is_dir($typeDir)) {
        continue;
    }

    HKDF::infoForType($type);

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($typeDir, FilesystemIterator::SKIP_DOTS),
    );

    foreach ($iterator as $fileInfo) {
        if (!$fileInfo instanceof SplFileInfo || !$fileInfo->isFile()) {
            continue;
        }

        $srcPath = $fileInfo->getPathname();
        $baseName = $fileInfo->getBasename();

        if ($baseName === '' || str_starts_with($baseName, '.')) {
            continue;
        }

        if (preg_match('/\.(encrypted|key|sidecar)$/i', $srcPath) === 1) {
            continue;
        }

        $rel = substr($srcPath, strlen($typeDir));
        $rel = str_replace(\DIRECTORY_SEPARATOR, '/', $rel);
        $rel = ltrim($rel, '/');
        $relDir = dirname($rel);

        if ($relDir === '.' || $relDir === '') {
            $destDir = "{$rootEncrypt}/{$type}";
        } else {
            $destDir = "{$rootEncrypt}/{$type}/{$relDir}";
        }

        if (!is_dir($destDir) && !@mkdir($destDir, 0755, true) && !is_dir($destDir)) {
            fwrite(STDERR, "Не удалось создать каталог: {$destDir}\n");
            $exit = 1;
            continue;
        }

        $stem = $fileInfo->getBasename('.' . $fileInfo->getExtension());
        if ($stem === '') {
            $stem = $baseName;
        }

        $encryptedPath = "{$destDir}/{$stem}.encrypted";
        $keyPath = "{$destDir}/{$stem}.key";

        try {
            $mediaKey = random_bytes(32);

            $buf = fopen('php://memory', 'w+b');
            if ($buf === false) {
                throw new RuntimeException('php://memory');
            }

            $out = Utils::streamFor($buf);
            $enc = new EncryptingStream($out, $mediaKey, $type);

            $in = fopen($srcPath, 'rb');
            if ($in === false) {
                throw new RuntimeException("Чтение: {$srcPath}");
            }

            while (!feof($in)) {
                $chunk = fread($in, 65536);
                if ($chunk === false) {
                    fclose($in);
                    throw new RuntimeException("Чтение: {$srcPath}");
                }
                if ($chunk !== '') {
                    $enc->write($chunk);
                }
            }
            fclose($in);

            $enc->close();
            $out->rewind();
            $cipherOut = $out->getContents();

            if (file_put_contents($encryptedPath, $cipherOut) === false) {
                throw new RuntimeException("Запись: {$encryptedPath}");
            }
            if (file_put_contents($keyPath, bin2hex($mediaKey) . "\n") === false) {
                throw new RuntimeException("Запись: {$keyPath}");
            }

            if ($type === 'VIDEO' || $type === 'AUDIO') {
                $sidecar = $enc->getSidecar();
                $sidecarPath = "{$destDir}/{$stem}.sidecar";
                if (file_put_contents($sidecarPath, $sidecar) === false) {
                    throw new RuntimeException("Запись: {$sidecarPath}");
                }
            }

            echo "{$srcPath} → {$encryptedPath}\n";
            ++$processed;
        } catch (Throwable $e) {
            fwrite(STDERR, "{$srcPath}: {$e->getMessage()}\n");
            $exit = 1;
        }
    }
}

if ($processed === 0) {
    echo "Файлов не найдено. Ожидается структура вроде {$rootOriginal}/IMAGE/файл...\n";
}

exit($exit);
