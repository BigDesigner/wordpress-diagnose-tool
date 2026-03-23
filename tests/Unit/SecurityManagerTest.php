<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use WPDiagnose\Core\SecurityManager;

final class SecurityManagerTest extends TestCase
{
    private string $storageDir;

    protected function setUp(): void
    {
        $this->storageDir = sys_get_temp_dir() . '/wp-diagnose-security-tests';
        if (!is_dir($this->storageDir)) {
            mkdir($this->storageDir, 0777, true);
        }

        foreach (['.ht-wp-diagnose-security.log', '.ht-wp-diagnose-rate-limits.json'] as $file) {
            $path = $this->storageDir . '/' . $file;
            if (is_file($path)) {
                unlink($path);
            }
        }
    }

    public function testLegacyTokenReceivesAdminAccess(): void
    {
        $manager = new SecurityManager(
            config: ['legacy_token' => 'legacy-secret'],
            server: ['REMOTE_ADDR' => '127.0.0.1'],
            get: ['token' => 'legacy-secret'],
            storageDir: $this->storageDir
        );

        $decision = $manager->authorize('dashboard');

        self::assertTrue($decision['allowed']);
        self::assertSame('admin', $decision['role']);
        self::assertSame('legacy', $decision['auth_mode']);
    }

    public function testSignedTokenSupportsOperatorRole(): void
    {
        $issuer = new SecurityManager(
            config: ['legacy_token' => 'legacy-secret', 'signing_secret' => 'test-signing-secret'],
            server: ['REMOTE_ADDR' => '127.0.0.1'],
            get: [],
            storageDir: $this->storageDir
        );

        $signedToken = $issuer->issueSignedToken('operator', 600);

        $manager = new SecurityManager(
            config: ['legacy_token' => 'legacy-secret', 'signing_secret' => 'test-signing-secret'],
            server: ['REMOTE_ADDR' => '127.0.0.1'],
            get: ['token' => $signedToken],
            storageDir: $this->storageDir
        );

        $decision = $manager->authorize('fix');

        self::assertTrue($decision['allowed']);
        self::assertSame('operator', $decision['role']);
        self::assertSame('signed', $decision['auth_mode']);
    }

    public function testViewerRoleCannotExecuteFixActions(): void
    {
        $issuer = new SecurityManager(
            config: ['legacy_token' => 'legacy-secret', 'signing_secret' => 'test-signing-secret'],
            server: ['REMOTE_ADDR' => '127.0.0.1'],
            get: [],
            storageDir: $this->storageDir
        );

        $signedToken = $issuer->issueSignedToken('viewer', 600);
        $manager = new SecurityManager(
            config: ['legacy_token' => 'legacy-secret', 'signing_secret' => 'test-signing-secret'],
            server: ['REMOTE_ADDR' => '127.0.0.1'],
            get: ['token' => $signedToken],
            storageDir: $this->storageDir
        );

        $decision = $manager->authorize('fix');

        self::assertFalse($decision['allowed']);
        self::assertSame(403, $decision['status']);
    }

    public function testRateLimitBlocksExcessiveRequests(): void
    {
        $config = [
            'legacy_token' => 'legacy-secret',
            'rate_limits' => [
                '*' => ['window' => 60, 'max' => 2],
                'fetch_report' => ['window' => 60, 'max' => 2],
            ],
        ];

        $manager = new SecurityManager(
            config: $config,
            server: ['REMOTE_ADDR' => '127.0.0.1'],
            get: ['token' => 'legacy-secret'],
            storageDir: $this->storageDir
        );

        self::assertTrue($manager->authorize('fetch_report')['allowed']);
        self::assertTrue($manager->authorize('fetch_report')['allowed']);

        $decision = $manager->authorize('fetch_report');

        self::assertFalse($decision['allowed']);
        self::assertSame(429, $decision['status']);
        self::assertNotNull($decision['retry_after']);
    }
}
