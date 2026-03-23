<?php
declare(strict_types=1);

namespace WPDiagnose\Core;

/**
 * Class Engine
 * 
 * Orchestrates the execution of multiple specialized diagnostic agents.
 */
class Engine
{
    /** @var array<string, DiagnosticInterface> Registered agents */
    private array $agents = [];

    /**
     * Registers a diagnostic agent with the engine.
     * 
     * @param DiagnosticInterface $agent The agent to register.
     */
    public function registerAgent(DiagnosticInterface $agent): void
    {
        $name = $agent->getName();
        $this->agents[$name] = $agent;
    }

    /**
     * Executes check routines for all registered agents.
     * 
     * @return array<string, array<string, mixed>>
     */
    public function runChecks(): array
    {
        $results = [];
        foreach ($this->agents as $name => $agent) {
            try {
                $results[$name] = $agent->check();
            } catch (\Throwable $e) {
                // If an agent crashes completely, return it as empty arrays to prevent frontend API failure.
                $results[$name] = [];
            }
        }
        return $results;
    }

    /**
     * Generates structured reports from all registered agents.
     * 
     * @return array<string, array<string, mixed>>
     */
    public function getReports(): array
    {
        $reports = [];
        foreach ($this->agents as $name => $agent) {
            try {
                $reports[$name] = $agent->report();
                if (!is_array($reports[$name])) {
                    $reports[$name] = []; // Enforce array output for agent
                }
            } catch (\Throwable $e) {
                // Provide empty array on error, ensuring Dashboard Alpine can still iterate.
                $reports[$name] = [];
            }
        }
        return $reports;
    }

    /**
     * Executes a fix action and normalizes the result for the API/UI layer.
     *
     * @return array{success: bool, message: string, data: mixed}
     */
    public function performFix(string $agentName, string $fixId): array
    {
        error_log("[WP Diagnose Engine] performAction POST Payload: " . print_r($_POST, true));
        error_log("[WP Diagnose Engine] performAction triggered - Agent: {$agentName}, ActionType: {$fixId}");
        
        if (!isset($this->agents[$agentName])) {
            error_log("[WP Diagnose Engine] WARNING: Agent {$agentName} not registered.");
            return [
                'success' => false,
                'message' => "Agent not registered: {$agentName}",
                'data' => null,
            ];
        }

        try {
            $result = $this->agents[$agentName]->fix($fixId);
            $response = [
                'success' => $result,
                'message' => $result ? "Action completed: {$fixId}" : "Action failed: {$fixId}",
                'data' => null,
            ];

            if (method_exists($this->agents[$agentName], 'getLastActionResult')) {
                $agentResponse = $this->agents[$agentName]->getLastActionResult();
                if (is_array($agentResponse)) {
                    $response = array_merge($response, $agentResponse);
                }
            }

            error_log("[WP Diagnose Engine] Action {$fixId} on {$agentName} returning " . ($response['success'] ? 'TRUE' : 'FALSE'));
            return $response;
        } catch (\Throwable $e) {
            error_log("[WP Diagnose Engine] ERROR during action {$fixId} on {$agentName}: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Action crashed: ' . $e->getMessage(),
                'data' => null,
            ];
        }
    }
}
