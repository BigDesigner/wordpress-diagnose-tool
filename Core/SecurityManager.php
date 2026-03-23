<?php
declare(strict_types=1);

namespace WPDiagnose\Core;

final class SecurityManager
{
    private const PLACEHOLDER_IP = 'CHANGE_TO_YOUR_STATIC_IP';

    /** @var array<string, mixed> */
    private array $config;

    /** @var array<string, mixed> */
    private array $server;

    /** @var array<string, mixed> */
    private array $get;

    private string $storageDir;

    /**
     * @param array<string, mixed> $config
     * @param array<string, mixed> $server
     * @param array<string, mixed> $get
     */
    public function __construct(array $config = [], array $server = [], array $get = [], ?string $storageDir = null)
    {
        $legacyToken = getenv('WPD_LEGACY_TOKEN') ?: 'SECURE_TOKEN_2026';
        $signingSecret = getenv('WPD_SIGNING_SECRET') ?: hash('sha256', 'wp-diagnose-signed-token|' . $legacyToken);
        $allowedIps = getenv('WPD_ALLOWED_IPS');
        $resolvedAllowedIps = is_string($allowedIps) && trim($allowedIps) !== ''
            ? array_values(array_filter(array_map('trim', explode(',', $allowedIps))))
            : ['127.0.0.1', '::1', self::PLACEHOLDER_IP];

        $defaults = [
            'legacy_token' => $legacyToken,
            'signing_secret' => $signingSecret,
            'allow_ips' => $resolvedAllowedIps,
            'trusted_proxy_headers' => ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'],
            'action_roles' => [
                'dashboard' => 'viewer',
                'fetch_report' => 'viewer',
                'fix' => 'operator',
                'self_destruct' => 'admin',
            ],
            'role_hierarchy' => [
                'viewer' => 1,
                'operator' => 2,
                'admin' => 3,
            ],
            'rate_limits' => [
                '*' => ['window' => 60, 'max' => 180],
                'dashboard' => ['window' => 60, 'max' => 120],
                'fetch_report' => ['window' => 60, 'max' => 90],
                'fix' => ['window' => 60, 'max' => 45],
                'self_destruct' => ['window' => 300, 'max' => 2],
            ],
            'audit_log_file' => '.ht-wp-diagnose-security.log',
            'rate_limit_file' => '.ht-wp-diagnose-rate-limits.json',
            'signed_token_audience' => 'wp-diagnose',
            'signed_token_clock_skew' => 5,
        ];

        $this->config = $this->mergeConfig($defaults, $config);
        $this->server = $server ?: $_SERVER;
        $this->get = $get ?: $_GET;
        $this->storageDir = rtrim($storageDir ?? getcwd(), '/\\');
        if (!is_dir($this->storageDir)) {
            @mkdir($this->storageDir, 0755, true);
        }
    }

    /**
     * @return array{allowed: bool, status: int, message: string, role: string|null, action: string, client_ip: string, auth_mode: string|null, claims: array<string, mixed>, retry_after: int|null}
     */
    public function authorize(?string $action = null): array
    {
        $actionName = $action ?: ($this->get['action'] ?? 'dashboard');
        $clientIp = $this->resolveClientIp();

        if (!$this->isIpAllowed($clientIp)) {
            return $this->deny(403, 'IP address is not allowed.', $actionName, $clientIp);
        }

        $authentication = $this->authenticate($this->extractToken());
        if (!$authentication['success']) {
            return $this->deny(401, $authentication['message'], $actionName, $clientIp);
        }

        $role = $authentication['role'];
        if (!$this->isRoleAuthorized($role, $actionName)) {
            return $this->deny(403, "Role '{$role}' is not permitted to execute '{$actionName}'.", $actionName, $clientIp, $role, $authentication['mode'], $authentication['claims']);
        }

        $rateLimit = $this->consumeRateLimit($clientIp, $actionName, $role);
        if (!$rateLimit['allowed']) {
            return $this->deny(429, 'Rate limit exceeded. Please retry shortly.', $actionName, $clientIp, $role, $authentication['mode'], $authentication['claims'], $rateLimit['retry_after']);
        }

        $decision = [
            'allowed' => true,
            'status' => 200,
            'message' => 'Authorized.',
            'role' => $role,
            'action' => $actionName,
            'client_ip' => $clientIp,
            'auth_mode' => $authentication['mode'],
            'claims' => $authentication['claims'],
            'retry_after' => null,
        ];

        $this->audit('ALLOW', $decision);
        return $decision;
    }

    /**
     * @param array{allowed: bool, status: int, message: string, role: string|null, action: string, client_ip: string, auth_mode: string|null, claims: array<string, mixed>, retry_after: int|null} $decision
     */
    public function emitDeniedResponse(array $decision): never
    {
        http_response_code($decision['status']);

        if ($this->isJsonRequest()) {
            while (ob_get_level()) {
                ob_end_clean();
            }

            header('Content-Type: application/json; charset=utf-8');
            if ($decision['retry_after'] !== null) {
                header('Retry-After: ' . $decision['retry_after']);
            }

            echo json_encode([
                'success' => false,
                'message' => $decision['message'],
                'security' => [
                    'action' => $decision['action'],
                    'role' => $decision['role'],
                    'status' => $decision['status'],
                ],
            ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            exit;
        }

        $safeMessage = htmlspecialchars($decision['message'], ENT_QUOTES, 'UTF-8');
        exit("<div style=\"background:#0f172a;color:#f8fafc;padding:32px;font-family:monospace;\"><strong>Access denied.</strong><div style=\"margin-top:8px;color:#f87171;\">{$safeMessage}</div></div>");
    }

    public function isJsonRequest(): bool
    {
        $accept = (string) ($this->server['HTTP_ACCEPT'] ?? '');
        return ($this->get['format'] ?? null) === 'json' || isset($this->get['action']) || str_contains($accept, 'application/json');
    }

    public function getAuditLogPath(): string
    {
        return $this->storageDir . DIRECTORY_SEPARATOR . $this->config['audit_log_file'];
    }

    public function issueSignedToken(string $role = 'operator', int $ttl = 900, array $claims = []): string
    {
        $now = time();
        $payload = array_merge([
            'aud' => $this->config['signed_token_audience'],
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $ttl,
            'role' => $role,
            'nonce' => bin2hex(random_bytes(8)),
        ], $claims);

        $encodedPayload = $this->base64UrlEncode(json_encode($payload, JSON_UNESCAPED_SLASHES));
        $signature = $this->base64UrlEncode(hash_hmac('sha256', $encodedPayload, (string) $this->config['signing_secret'], true));

        return $encodedPayload . '.' . $signature;
    }

    /**
     * @param array<string, mixed> $defaults
     * @param array<string, mixed> $config
     * @return array<string, mixed>
     */
    private function mergeConfig(array $defaults, array $config): array
    {
        foreach ($config as $key => $value) {
            if (is_array($value) && isset($defaults[$key]) && is_array($defaults[$key])) {
                $defaults[$key] = $this->mergeConfig($defaults[$key], $value);
                continue;
            }

            $defaults[$key] = $value;
        }

        return $defaults;
    }

    private function extractToken(): ?string
    {
        $queryToken = $this->get['token'] ?? null;
        if (is_string($queryToken) && $queryToken !== '') {
            return trim($queryToken);
        }

        $authHeader = (string) ($this->server['HTTP_AUTHORIZATION'] ?? $this->server['Authorization'] ?? '');
        if (preg_match('/Bearer\s+(.+)/i', $authHeader, $matches) === 1) {
            return trim($matches[1]);
        }

        $headerToken = $this->server['HTTP_X_WPD_TOKEN'] ?? null;
        return is_string($headerToken) && $headerToken !== '' ? trim($headerToken) : null;
    }

    private function resolveClientIp(): string
    {
        foreach ($this->config['trusted_proxy_headers'] as $header) {
            if (!isset($this->server[$header]) || !is_string($this->server[$header])) {
                continue;
            }

            $value = trim($this->server[$header]);
            if ($value === '') {
                continue;
            }

            $parts = array_map('trim', explode(',', $value));
            foreach ($parts as $part) {
                if (filter_var($part, FILTER_VALIDATE_IP)) {
                    return $part;
                }
            }
        }

        return '0.0.0.0';
    }

    private function isIpAllowed(string $clientIp): bool
    {
        $allowedIps = $this->config['allow_ips'];
        if (in_array('*', $allowedIps, true) || in_array(self::PLACEHOLDER_IP, $allowedIps, true)) {
            return true;
        }

        return in_array($clientIp, $allowedIps, true);
    }

    /**
     * @return array{success: bool, message: string, role: string|null, mode: string|null, claims: array<string, mixed>}
     */
    private function authenticate(?string $token): array
    {
        if ($token === null || $token === '') {
            return [
                'success' => false,
                'message' => 'Missing access token.',
                'role' => null,
                'mode' => null,
                'claims' => [],
            ];
        }

        if (hash_equals((string) $this->config['legacy_token'], $token)) {
            return [
                'success' => true,
                'message' => 'Legacy token accepted.',
                'role' => 'admin',
                'mode' => 'legacy',
                'claims' => [],
            ];
        }

        $parts = explode('.', $token);
        if (count($parts) !== 2) {
            return [
                'success' => false,
                'message' => 'Invalid token format.',
                'role' => null,
                'mode' => null,
                'claims' => [],
            ];
        }

        [$encodedPayload, $encodedSignature] = $parts;
        $expectedSignature = $this->base64UrlEncode(hash_hmac('sha256', $encodedPayload, (string) $this->config['signing_secret'], true));
        if (!hash_equals($expectedSignature, $encodedSignature)) {
            return [
                'success' => false,
                'message' => 'Signed token verification failed.',
                'role' => null,
                'mode' => null,
                'claims' => [],
            ];
        }

        $payloadJson = $this->base64UrlDecode($encodedPayload);
        $claims = json_decode($payloadJson, true);
        if (!is_array($claims)) {
            return [
                'success' => false,
                'message' => 'Signed token payload is invalid.',
                'role' => null,
                'mode' => null,
                'claims' => [],
            ];
        }

        $audience = $claims['aud'] ?? null;
        if ($audience !== $this->config['signed_token_audience']) {
            return [
                'success' => false,
                'message' => 'Signed token audience mismatch.',
                'role' => null,
                'mode' => null,
                'claims' => $claims,
            ];
        }

        $now = time();
        $skew = (int) $this->config['signed_token_clock_skew'];
        if (isset($claims['nbf']) && (int) $claims['nbf'] > ($now + $skew)) {
            return [
                'success' => false,
                'message' => 'Signed token is not yet valid.',
                'role' => null,
                'mode' => null,
                'claims' => $claims,
            ];
        }

        if (!isset($claims['exp']) || (int) $claims['exp'] < ($now - $skew)) {
            return [
                'success' => false,
                'message' => 'Signed token has expired.',
                'role' => null,
                'mode' => null,
                'claims' => $claims,
            ];
        }

        $role = $claims['role'] ?? null;
        if (!is_string($role) || !isset($this->config['role_hierarchy'][$role])) {
            return [
                'success' => false,
                'message' => 'Signed token role is invalid.',
                'role' => null,
                'mode' => null,
                'claims' => $claims,
            ];
        }

        return [
            'success' => true,
            'message' => 'Signed token accepted.',
            'role' => $role,
            'mode' => 'signed',
            'claims' => $claims,
        ];
    }

    private function isRoleAuthorized(string $role, string $action): bool
    {
        $requiredRole = $this->config['action_roles'][$action] ?? $this->config['action_roles']['dashboard'];
        $hierarchy = $this->config['role_hierarchy'];

        return ($hierarchy[$role] ?? 0) >= ($hierarchy[$requiredRole] ?? PHP_INT_MAX);
    }

    /**
     * @return array{allowed: bool, retry_after: int|null}
     */
    private function consumeRateLimit(string $clientIp, string $action, string $role): array
    {
        $policy = $this->config['rate_limits'][$action] ?? $this->config['rate_limits']['*'];
        $window = max(1, (int) ($policy['window'] ?? 60));
        $max = max(1, (int) ($policy['max'] ?? 60));
        $path = $this->storageDir . DIRECTORY_SEPARATOR . $this->config['rate_limit_file'];
        $bucketKey = hash('sha256', $clientIp . '|' . $action . '|' . $role);
        $now = time();

        $handle = fopen($path, 'c+');
        if ($handle === false) {
            return ['allowed' => true, 'retry_after' => null];
        }

        try {
            if (!flock($handle, LOCK_EX)) {
                return ['allowed' => true, 'retry_after' => null];
            }

            $contents = stream_get_contents($handle);
            $state = json_decode($contents ?: '{}', true);
            if (!is_array($state)) {
                $state = [];
            }

            $cutoff = $now - $window;
            foreach ($state as $key => $timestamps) {
                if (!is_array($timestamps)) {
                    unset($state[$key]);
                    continue;
                }

                $state[$key] = array_values(array_filter($timestamps, static fn($timestamp): bool => (int) $timestamp >= $cutoff));
                if ($state[$key] === []) {
                    unset($state[$key]);
                }
            }

            $bucket = $state[$bucketKey] ?? [];
            if (count($bucket) >= $max) {
                $oldest = (int) min($bucket);
                return ['allowed' => false, 'retry_after' => max(1, $window - ($now - $oldest))];
            }

            $bucket[] = $now;
            $state[$bucketKey] = $bucket;

            rewind($handle);
            ftruncate($handle, 0);
            fwrite($handle, json_encode($state, JSON_UNESCAPED_SLASHES));
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }

        return ['allowed' => true, 'retry_after' => null];
    }

    /**
     * @param array<string, mixed> $claims
     * @return array{allowed: bool, status: int, message: string, role: string|null, action: string, client_ip: string, auth_mode: string|null, claims: array<string, mixed>, retry_after: int|null}
     */
    private function deny(int $status, string $message, string $action, string $clientIp, ?string $role = null, ?string $authMode = null, array $claims = [], ?int $retryAfter = null): array
    {
        $decision = [
            'allowed' => false,
            'status' => $status,
            'message' => $message,
            'role' => $role,
            'action' => $action,
            'client_ip' => $clientIp,
            'auth_mode' => $authMode,
            'claims' => $claims,
            'retry_after' => $retryAfter,
        ];

        $this->audit('DENY', $decision);
        return $decision;
    }

    /**
     * @param array<string, mixed> $context
     */
    private function audit(string $event, array $context): void
    {
        $line = sprintf(
            "[%s] [%s] ip=%s action=%s role=%s mode=%s status=%s message=%s\n",
            gmdate('Y-m-d H:i:s'),
            $event,
            $context['client_ip'] ?? 'unknown',
            $context['action'] ?? 'unknown',
            $context['role'] ?? 'guest',
            $context['auth_mode'] ?? 'none',
            $context['status'] ?? 'n/a',
            $context['message'] ?? ''
        );

        @file_put_contents($this->getAuditLogPath(), $line, FILE_APPEND | LOCK_EX);
    }

    private function base64UrlEncode(string $payload): string
    {
        return rtrim(strtr(base64_encode($payload), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $payload): string
    {
        $remainder = strlen($payload) % 4;
        if ($remainder > 0) {
            $payload .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($payload, '-_', '+/')) ?: '';
    }
}
