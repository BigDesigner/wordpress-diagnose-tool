<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use WPDiagnose\Core\DiagnosticInterface;
use WPDiagnose\Core\Engine;

final class EngineTest extends TestCase
{
    public function testPerformFixReturnsAgentActionPayload(): void
    {
        $engine = new Engine();
        $engine->registerAgent(new class implements DiagnosticInterface {
            public function check(): array
            {
                return ['ok' => ['status' => 'OK']];
            }

            public function fix(string $id): bool
            {
                return $id === 'repair';
            }

            public function report(): array
            {
                return $this->check();
            }

            public function getName(): string
            {
                return 'FakeAgent';
            }

            public function getLastActionResult(): array
            {
                return [
                    'success' => true,
                    'message' => 'Synthetic repair completed.',
                    'data' => ['id' => 'repair'],
                ];
            }
        });

        $result = $engine->performFix('FakeAgent', 'repair');

        self::assertTrue($result['success']);
        self::assertSame('Synthetic repair completed.', $result['message']);
        self::assertSame(['id' => 'repair'], $result['data']);
    }

    public function testPerformFixHandlesMissingAgent(): void
    {
        $engine = new Engine();

        $result = $engine->performFix('MissingAgent', 'noop');

        self::assertFalse($result['success']);
        self::assertStringContainsString('Agent not registered', $result['message']);
    }
}
