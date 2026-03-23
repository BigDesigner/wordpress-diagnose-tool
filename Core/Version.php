<?php
declare(strict_types=1);

namespace WPDiagnose\Core;

final class Version
{
    public const NUMBER = '0.2.9-beta';

    public static function current(): string
    {
        $versionFile = dirname(__DIR__) . '/VERSION';
        if (is_file($versionFile)) {
            $version = trim((string) @file_get_contents($versionFile));
            if ($version !== '') {
                return $version;
            }
        }

        return self::NUMBER;
    }

    public static function label(): string
    {
        return 'v' . self::current();
    }
}
