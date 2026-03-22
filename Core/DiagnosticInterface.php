<?php
declare(strict_types=1);

namespace WPDiagnose\Core;

/**
 * Interface DiagnosticInterface
 * 
 * Defines the contract for all health check agents.
 */
interface DiagnosticInterface
{
    /**
     * Executes the diagnostic checks and returns raw results.
     * 
     * @return array<string, mixed>
     */
    public function check(): array;

    /**
     * Attempts to fix a specific health issue.
     * 
     * @param string $id The unique identifier for the issue to fix.
     * @return bool True if the fix was successful, false otherwise.
     */
    public function fix(string $id): bool;

    /**
     * Provides a structured report of the current state.
     * 
     * @return array<string, mixed>
     */
    public function report(): array;

    /**
     * Returns the human-readable name of the inspector.
     * 
     * @return string
     */
    public function getName(): string;
}
