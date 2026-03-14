<?php
namespace Fox;

class CSRF
{
    private const TOKEN_KEY = 'X-CSRF-TOKEN-LIST';

    private static function startSession(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        if (!isset($_SESSION[self::TOKEN_KEY]) || !is_array($_SESSION[self::TOKEN_KEY])) {
            $_SESSION[self::TOKEN_KEY] = [];
        }
    }

    private static function randomToken(): string
    {
        self::startSession();

        // Better token generation than shuffle/hash
        $token = bin2hex(random_bytes(32));

        self::setToken($token);

        return $token;
    }

    private static function getRealIpAddr(): string
    {
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            return $_SERVER['HTTP_CLIENT_IP'];
        }

        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return $_SERVER['HTTP_X_FORWARDED_FOR'];
        }

        return $_SERVER['REMOTE_ADDR'] ?? '';
    }

    private static function setToken(string $token): void
    {
        self::startSession();
        $_SESSION[self::TOKEN_KEY][] = $token;
    }

    private static function checkToken(?string $token): bool
    {
        self::startSession();

        if (empty($token)) {
            return false;
        }

        $tokenList = $_SESSION[self::TOKEN_KEY];

        if (in_array($token, $tokenList, true)) {
            self::removeToken($token);
            return true;
        }

        return false;
    }

    private static function removeToken(string $token): void
    {
        self::startSession();

        $tokenList = $_SESSION[self::TOKEN_KEY];
        $index = array_search($token, $tokenList, true);

        if ($index !== false) {
            unset($tokenList[$index]);
            $_SESSION[self::TOKEN_KEY] = array_values($tokenList);
        }
    }

    private static function authToken(array $arrData): bool
    {
        if (empty($arrData)) {
            return false;
        }

        if ($arrData["method"] !== $_SERVER["REQUEST_METHOD"] && $arrData["method"] !== "ALL") {
            return true;
        }

        $token = $arrData["token"] ?? null;

        return self::checkToken($token);
    }

    public static function token(): string
    {
        return self::randomToken();
    }

    public static function get(): bool
    {
        return self::authToken([
            "method" => "GET",
            "token" => $_GET['_token'] ?? null
        ]);
    }

    public static function post(): bool
    {
        return self::authToken([
            "method" => "POST",
            "token" => $_POST['_token'] ?? null
        ]);
    }

    public static function all(): bool
    {
        if (isset($_POST['_token'])) {
            return self::authToken([
                "method" => "ALL",
                "token" => $_POST['_token']
            ]);
        }

        if (isset($_GET['_token'])) {
            return self::authToken([
                "method" => "ALL",
                "token" => $_GET['_token']
            ]);
        }

        return self::authToken([
            "method" => "ALL",
            "token" => null
        ]);
    }

    public static function flushToken(): void
    {
        self::startSession();
        $_SESSION[self::TOKEN_KEY] = [];
    }
}
?>