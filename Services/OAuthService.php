<?php

namespace Plugin\Oauth\Services;

use App\Exceptions\ApiException;
use App\Models\User;
use App\Services\Auth\LoginService;
use App\Services\Auth\RegisterService;
use App\Services\Plugin\HookManager;
use App\Services\Plugin\PluginConfigService;
use App\Services\UserService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class OAuthService
{
    protected array $config;

    public function __construct(
        protected LoginService $loginService,
        protected RegisterService $registerService,
        protected UserService $userService,
        PluginConfigService $pluginConfigService
    ) {
        $this->config = $pluginConfigService->getDbConfig('oauth');
    }

    public function getEnabledProviders(): array
    {
        $items = [];

        foreach ($this->getProviders() as $driver => $provider) {
            if (!$this->isConfigured($provider)) {
                continue;
            }

            $items[] = [
                'driver' => $driver,
                'label' => $provider['label'],
            ];
        }

        return $items;
    }

    public function getUserBindings(User $user): array
    {
        $items = [];

        foreach ($this->getProviders() as $driver => $provider) {
            $providerColumn = $provider['user_column'];
            $bound = filled($user->{$providerColumn});

            if (!$bound && !$this->isConfigured($provider)) {
                continue;
            }

            $items[] = [
                'driver' => $driver,
                'label' => $provider['label'],
                'bound' => $bound,
            ];
        }

        return $items;
    }

    public function prepareBind(string $driver, User $user): array
    {
        $provider = $this->getProvider($driver);
        if (!$provider || !$this->isConfigured($provider)) {
            return [false, [400, __('This OAuth provider is not configured')]];
        }

        $bindToken = Str::random(40);
        Cache::put($this->getBindCacheKey($bindToken), [
            'user_id' => $user->id,
            'driver' => $driver,
        ], now()->addMinutes(10));

        return [true, [
            'bind_token' => $bindToken,
        ]];
    }

    public function unbind(string $driver, User $user): array
    {
        $provider = $this->getProvider($driver);
        if (!$provider) {
            return [false, [404, __('Unsupported OAuth provider')]];
        }

        $providerColumn = $provider['user_column'];
        if (!$user->{$providerColumn}) {
            return [true, true];
        }

        $user->{$providerColumn} = null;
        if (!$user->save()) {
            return [false, [500, __('Failed to unbind :provider account', [
                'provider' => $provider['label'],
            ])]];
        }

        return [true, true];
    }

    public function confirmRegister(Request $request, string $token): array
    {
        if ($token === '') {
            return [false, [400, __('The OAuth registration confirmation is invalid or has expired')]];
        }

        $pendingRegister = Cache::get($this->getPendingRegisterCacheKey($token));
        if (
            !$pendingRegister
            || empty($pendingRegister['driver'])
            || empty($pendingRegister['provider_id'])
        ) {
            return [false, [400, __('The OAuth registration confirmation is invalid or has expired')]];
        }

        $provider = $this->getProvider((string) $pendingRegister['driver']);
        if (!$provider) {
            return [false, [400, __('Unsupported OAuth provider')]];
        }

        $providerColumn = $provider['user_column'];
        $providerId = trim((string) $pendingRegister['provider_id']);
        $email = strtolower(trim((string) ($pendingRegister['email'] ?? '')));

        $user = User::where($providerColumn, $providerId)->first();
        if (!$user && $email !== '') {
            $user = User::byEmail($email)->first();
            if ($user) {
                if ($user->{$providerColumn} && $user->{$providerColumn} !== $providerId) {
                    return [false, [400, __('This email is already linked to another :provider account', [
                        'provider' => $provider['label'],
                    ])]];
                }

                $user->{$providerColumn} = $providerId;
                if (!$user->save()) {
                    return [false, [500, __('Failed to link :provider account', [
                        'provider' => $provider['label'],
                    ])]];
                }
            }
        }

        if (!$user) {
            [$success, $result] = $this->registerOauthUser(
                $request,
                $providerColumn,
                $providerId,
                $email,
                $pendingRegister['invite_code'] ?? null
            );

            if (!$success) {
                return [false, $result];
            }

            $user = $result;
        }

        if ($user->banned) {
            return [false, [400, __('Your account has been suspended')]];
        }

        $user->last_login_at = time();
        $user->save();

        HookManager::call('user.login.after', $user);

        $loginUrl = $this->loginService->generateQuickLoginUrl($user, $pendingRegister['redirect'] ?? 'dashboard');
        if (!$loginUrl) {
            return [false, [500, __('Failed to generate quick login URL')]];
        }

        Cache::forget($this->getPendingRegisterCacheKey($token));

        return [true, $loginUrl];
    }

    public function redirect(string $driver, Request $request): RedirectResponse
    {
        $provider = $this->getProvider($driver);
        $scene = $this->normalizeScene($request->query('scene'));

        if (!$provider || !$this->isConfigured($provider)) {
            return redirect()->away($this->buildFrontendUrl($scene, [
                'oauth_error' => __('This OAuth provider is not configured'),
            ]));
        }

        $bindToken = null;
        if ($scene === 'bind') {
            $bindToken = trim((string) $request->query('bind_token'));
            $bindState = $bindToken !== '' ? Cache::get($this->getBindCacheKey($bindToken)) : null;

            if (
                !$bindState
                || ($bindState['driver'] ?? null) !== $driver
                || empty($bindState['user_id'])
            ) {
                return redirect()->away($this->buildFrontendUrl('bind', [
                    'oauth_error' => __('The OAuth binding request is invalid or has expired'),
                ]));
            }
        }

        $state = Str::random(40);
        $browserState = Str::random(40);
        Cache::put($this->getStateCacheKey($state), [
            'driver' => $driver,
            'scene' => $scene,
            'redirect' => trim((string) $request->query('redirect', 'dashboard')),
            'invite_code' => trim((string) $request->query('invite_code')),
            'browser_state' => $browserState,
            'bind_token' => $bindToken,
        ], now()->addMinutes(10));

        return redirect()->away($this->buildAuthorizeUrl($provider, $state))
            ->withCookie(cookie()->make(
                $this->getStateCookieName($state),
                $browserState,
                10,
                null,
                null,
                $request->isSecure(),
                true,
                false,
                'lax'
            ));
    }

    public function callback(string $driver, Request $request): RedirectResponse
    {
        $provider = $this->getProvider($driver);
        if (!$provider || !$this->isConfigured($provider)) {
            return redirect()->away($this->buildFrontendUrl('login', [
                'oauth_error' => __('This OAuth provider is not configured'),
            ]));
        }

        $state = (string) $request->query('state');
        if ($state === '') {
            return redirect()->away($this->buildFrontendUrl('login', [
                'oauth_error' => __('The OAuth state is missing'),
            ]));
        }

        $stateCookieName = $this->getStateCookieName($state);
        $forgetStateCookie = cookie()->forget($stateCookieName);
        $stateCookie = (string) $request->cookie($stateCookieName);
        $oauthState = Cache::pull($this->getStateCacheKey($state));
        $scene = $this->normalizeScene(is_array($oauthState) ? ($oauthState['scene'] ?? null) : null);

        if (
            !$oauthState
            || ($oauthState['driver'] ?? null) !== $driver
            || $stateCookie === ''
            || !hash_equals((string) ($oauthState['browser_state'] ?? ''), $stateCookie)
        ) {
            return redirect()->away($this->buildFrontendUrl($scene, [
                'oauth_error' => __('The OAuth state is invalid or has expired'),
            ]))->withCookie($forgetStateCookie);
        }

        if ($request->filled('error')) {
            return redirect()->away($this->buildFrontendUrl($scene, [
                'oauth_error' => __('OAuth authorization failed'),
            ]))->withCookie($forgetStateCookie);
        }

        try {
            $tokenData = $this->exchangeCode($provider, (string) $request->query('code'));
            $profile = $this->fetchUserProfile($provider, $tokenData['access_token']);

            if ($scene === 'bind') {
                [$success, $result] = $this->bindUser($provider, $profile, (string) ($oauthState['bind_token'] ?? ''));
                if (!$success) {
                    return redirect()->away($this->buildFrontendUrl('bind', [
                        'oauth_error' => $result[1] ?? __('OAuth bind failed'),
                    ]))->withCookie($forgetStateCookie);
                }

                return redirect()->away($this->buildFrontendUrl('bind', [
                    'oauth_success' => __(':provider account linked successfully', [
                        'provider' => $provider['label'],
                    ]),
                ]))->withCookie($forgetStateCookie);
            }

            [$success, $result] = $this->resolveUser($request, $provider, $profile, $oauthState);
            if (!$success) {
                if (($result[2] ?? null) === 'confirm_register') {
                    return redirect()->away($this->buildFrontendUrl($scene, [
                        'oauth_confirm_token' => $result[3] ?? '',
                        'oauth_provider' => $provider['driver'],
                        'oauth_email' => $result[4] ?? '',
                    ]))->withCookie($forgetStateCookie);
                }

                $query = [
                    'oauth_error' => $result[1] ?? __('OAuth login failed'),
                ];

                if (($result[2] ?? null) === 'bind_existing') {
                    $query['oauth_hint'] = 'bind_existing';
                    $query['oauth_provider'] = $provider['driver'];
                }

                return redirect()->away($this->buildFrontendUrl($scene, $query))->withCookie($forgetStateCookie);
            }

            if ($result->banned) {
                return redirect()->away($this->buildFrontendUrl($scene, [
                    'oauth_error' => __('Your account has been suspended'),
                ]))->withCookie($forgetStateCookie);
            }

            $result->last_login_at = time();
            $result->save();

            HookManager::call('user.login.after', $result);

            $loginUrl = $this->loginService->generateQuickLoginUrl($result, $oauthState['redirect'] ?: 'dashboard');
            if (!$loginUrl) {
                return redirect()->away($this->buildFrontendUrl($scene, [
                    'oauth_error' => __('Failed to generate quick login URL'),
                ]))->withCookie($forgetStateCookie);
            }

            return redirect()->away($loginUrl)->withCookie($forgetStateCookie);
        } catch (\Throwable $e) {
            report($e);

            return redirect()->away($this->buildFrontendUrl($scene, [
                'oauth_error' => __('OAuth login failed'),
            ]))->withCookie($forgetStateCookie);
        }
    }

    protected function resolveUser(Request $request, array $provider, array $profile, array $oauthState): array
    {
        $providerId = trim((string) ($profile['id'] ?? ''));
        if ($providerId === '') {
            return [false, [400, __('Unable to get your account identifier from :provider', [
                'provider' => $provider['label'],
            ])]];
        }

        $providerColumn = $provider['user_column'];
        $user = User::where($providerColumn, $providerId)->first();
        if ($user) {
            return [true, $user];
        }

        $email = strtolower(trim((string) ($profile['email'] ?? '')));
        if ($email !== '') {
            $user = User::byEmail($email)->first();
            if ($user) {
                if ($user->{$providerColumn} && $user->{$providerColumn} !== $providerId) {
                    return [false, [400, __('This email is already linked to another :provider account', [
                        'provider' => $provider['label'],
                    ])]];
                }

                $user->{$providerColumn} = $providerId;
                if (!$user->save()) {
                    return [false, [500, __('Failed to link :provider account', [
                        'provider' => $provider['label'],
                    ])]];
                }

                return [true, $user];
            }
        }

        if ((int) admin_setting('stop_register', 0)) {
            return [false, [400, __(':provider login currently requires binding an existing account first. Please log in to your site account and bind :provider from the profile page before using it.', [
                'provider' => $provider['label'],
            ]), 'bind_existing']];
        }

        if ($this->getProviderRegisterMode($provider['driver']) === 'bind_existing') {
            return [false, [400, __(':provider login currently requires binding an existing account first. Please log in to your site account and bind :provider from the profile page before using it.', [
                'provider' => $provider['label'],
            ]), 'bind_existing']];
        }

        if ($email === '') {
            return [false, [400, __('Unable to get your email from :provider', [
                'provider' => $provider['label'],
            ])]];
        }

        $confirmToken = Str::random(40);
        Cache::put($this->getPendingRegisterCacheKey($confirmToken), [
            'driver' => $provider['driver'],
            'provider_id' => $providerId,
            'email' => $email,
            'invite_code' => $oauthState['invite_code'] ?? null,
            'redirect' => $oauthState['redirect'] ?? 'dashboard',
        ], now()->addMinutes(10));

        return [false, [409, __('Please confirm account creation before registering with :provider', [
            'provider' => $provider['label'],
        ]), 'confirm_register', $confirmToken, $email]];
    }

    protected function bindUser(array $provider, array $profile, string $bindToken): array
    {
        $providerId = trim((string) ($profile['id'] ?? ''));
        if ($providerId === '') {
            return [false, [400, __('Unable to get your account identifier from :provider', [
                'provider' => $provider['label'],
            ])]];
        }

        if ($bindToken === '') {
            return [false, [400, __('The OAuth binding request is invalid or has expired')]];
        }

        $bindState = Cache::pull($this->getBindCacheKey($bindToken));
        if (
            !$bindState
            || ($bindState['driver'] ?? null) !== $provider['driver']
            || empty($bindState['user_id'])
        ) {
            return [false, [400, __('The OAuth binding request is invalid or has expired')]];
        }

        $user = User::find($bindState['user_id']);
        if (!$user) {
            return [false, [404, __('The user does not exist')]];
        }

        $providerColumn = $provider['user_column'];
        $boundUser = User::where($providerColumn, $providerId)->first();
        if ($boundUser && $boundUser->id !== $user->id) {
            return [false, [400, __('This :provider account is already linked to another user', [
                'provider' => $provider['label'],
            ])]];
        }

        if ($user->{$providerColumn} && $user->{$providerColumn} !== $providerId) {
            return [false, [400, __('Your account is already linked to another :provider account', [
                'provider' => $provider['label'],
            ])]];
        }

        $user->{$providerColumn} = $providerId;
        if (!$user->save()) {
            return [false, [500, __('Failed to link :provider account', [
                'provider' => $provider['label'],
            ])]];
        }

        return [true, $user];
    }

    protected function registerOauthUser(
        Request $request,
        string $providerColumn,
        string $providerId,
        string $email,
        ?string $inviteCode
    ): array {
        if ((int) admin_setting('register_limit_by_ip_enable', 0)) {
            $registerCountByIP = Cache::get('PLUGIN_OAUTH_REGISTER_IP_' . $request->ip()) ?? 0;
            if ((int) $registerCountByIP >= (int) admin_setting('register_limit_count', 3)) {
                return [false, [429, __('Register frequently, please try again after :minute minute', [
                    'minute' => admin_setting('register_limit_expire', 60),
                ])]];
            }
        }

        if ((int) admin_setting('email_whitelist_enable', 0)) {
            if (!\App\Utils\Helper::emailSuffixVerify(
                $email,
                admin_setting('email_whitelist_suffix', \App\Utils\Dict::EMAIL_WHITELIST_SUFFIX_DEFAULT)
            )) {
                return [false, [400, __('Email suffix is not in the Whitelist')]];
            }
        }

        if ((int) admin_setting('email_gmail_limit_enable', 0)) {
            $prefix = explode('@', $email)[0];
            if (strpos($prefix, '.') !== false || strpos($prefix, '+') !== false) {
                return [false, [400, __('Gmail alias is not supported')]];
            }
        }

        if ((int) admin_setting('stop_register', 0)) {
            return [false, [400, __('Registration has closed')]];
        }

        if ((int) admin_setting('invite_force', 0) && !$inviteCode) {
            return [false, [422, __('You must use the invitation code to register')]];
        }

        if (User::byEmail($email)->exists()) {
            return [false, [400201, __('Email already exists')]];
        }

        $registerRequest = $request->duplicate();
        $registerRequest->merge([
            'email' => $email,
            'invite_code' => $inviteCode,
        ]);

        HookManager::call('user.register.before', $registerRequest);

        try {
            $inviteUserId = $inviteCode ? $this->registerService->handleInviteCode($inviteCode) : null;
        } catch (ApiException $e) {
            return [false, [$e->getCode(), $e->getMessage()]];
        }

        $user = $this->userService->createUser([
            'email' => $email,
            'password' => Str::random(32),
            'invite_user_id' => $inviteUserId,
        ]);
        $user->{$providerColumn} = $providerId;

        if (!$user->save()) {
            return [false, [500, __('Register failed')]];
        }

        HookManager::call('user.register.after', $user);

        $user->last_login_at = time();
        $user->save();

        if ((int) admin_setting('register_limit_by_ip_enable', 0)) {
            $registerCountByIP = Cache::get('PLUGIN_OAUTH_REGISTER_IP_' . $request->ip()) ?? 0;
            Cache::put(
                'PLUGIN_OAUTH_REGISTER_IP_' . $request->ip(),
                (int) $registerCountByIP + 1,
                (int) admin_setting('register_limit_expire', 60) * 60
            );
        }

        return [true, $user];
    }

    protected function fetchUserProfile(array $provider, string $accessToken): array
    {
        return match ($provider['driver']) {
            'google' => $this->fetchGoogleProfile($provider, $accessToken),
            'github' => $this->fetchGithubProfile($provider, $accessToken),
            'linuxdo' => $this->fetchLinuxdoProfile($provider, $accessToken),
            default => throw new \RuntimeException(__('Unsupported OAuth provider')),
        };
    }

    protected function fetchGoogleProfile(array $provider, string $accessToken): array
    {
        $response = Http::acceptJson()
            ->withToken($accessToken)
            ->timeout(15)
            ->get($provider['userinfo_url']);

        if ($response->failed()) {
            throw new \RuntimeException(__('Failed to fetch Google user information'));
        }

        $data = $response->json();

        return [
            'id' => (string) ($data['sub'] ?? ''),
            'email' => $data['email'] ?? '',
            'email_verified' => (bool) ($data['email_verified'] ?? false),
        ];
    }

    protected function fetchGithubProfile(array $provider, string $accessToken): array
    {
        $userResponse = Http::acceptJson()
            ->withHeaders(['User-Agent' => $this->getUserAgent()])
            ->withToken($accessToken)
            ->timeout(15)
            ->get($provider['userinfo_url']);

        if ($userResponse->failed()) {
            throw new \RuntimeException(__('Failed to fetch GitHub user information'));
        }

        $emailResponse = Http::acceptJson()
            ->withHeaders(['User-Agent' => $this->getUserAgent()])
            ->withToken($accessToken)
            ->timeout(15)
            ->get($provider['emails_url']);

        if ($emailResponse->failed()) {
            throw new \RuntimeException(__('Failed to fetch GitHub user email'));
        }

        $emailItem = collect($emailResponse->json())
            ->first(fn($item) => ($item['primary'] ?? false))
            ?? collect($emailResponse->json())->first();

        if (!$emailItem || empty($emailItem['email'])) {
            throw new \RuntimeException(__('Failed to fetch GitHub user email'));
        }

        $data = $userResponse->json();

        return [
            'id' => (string) ($data['id'] ?? ''),
            'email' => $emailItem['email'] ?? '',
            'email_verified' => (bool) ($emailItem['verified'] ?? false),
        ];
    }

    protected function fetchLinuxdoProfile(array $provider, string $accessToken): array
    {
        $response = Http::acceptJson()
            ->withToken($accessToken)
            ->timeout(15)
            ->get($provider['userinfo_url']);

        if ($response->failed()) {
            throw new \RuntimeException(__('Failed to fetch LinuxDO user information'));
        }

        $data = $response->json();

        return [
            'id' => (string) ($data['id'] ?? ''),
            'email' => $data['email'] ?? '',
            'email_verified' => (bool) ($data['email_verified'] ?? false),
        ];
    }

    protected function exchangeCode(array $provider, string $code): array
    {
        if ($code === '') {
            throw new \RuntimeException(__('Authorization code is missing'));
        }

        $payload = [
            'client_id' => $provider['client_id'],
            'client_secret' => $provider['client_secret'],
            'redirect_uri' => $this->getRedirectUri($provider['driver']),
            'code' => $code,
        ];

        if ($provider['driver'] !== 'github') {
            $payload['grant_type'] = 'authorization_code';
        }

        $response = Http::asForm()
            ->acceptJson()
            ->timeout(15)
            ->post($provider['token_url'], $payload);

        if ($response->failed()) {
            throw new \RuntimeException(__('Failed to exchange authorization code'));
        }

        $data = $response->json();
        if (empty($data['access_token'])) {
            throw new \RuntimeException(__('The OAuth provider did not return an access token'));
        }

        return $data;
    }

    protected function buildAuthorizeUrl(array $provider, string $state): string
    {
        $params = [
            'client_id' => $provider['client_id'],
            'redirect_uri' => $this->getRedirectUri($provider['driver']),
            'response_type' => 'code',
            'scope' => implode(' ', $provider['scopes']),
            'state' => $state,
        ];

        if ($provider['driver'] === 'google') {
            $params['access_type'] = 'online';
            $params['prompt'] = 'select_account';
        }

        return $provider['authorize_url'] . '?' . http_build_query($params);
    }

    protected function buildFrontendUrl(?string $scene, array $query = []): string
    {
        $scene = $this->normalizeScene($scene);
        $baseUrl = rtrim((string) (admin_setting('app_url') ?: config('app.url') ?: url('/')), '/');
        $hash = $scene === 'bind' ? '#/app/profile' : '#/' . $scene;
        if ($query) {
            $hash .= '?' . http_build_query($query);
        }

        return $baseUrl . '/' . $hash;
    }

    protected function getRedirectUri(string $driver): string
    {
        $baseUrl = rtrim((string) (admin_setting('app_url') ?: config('app.url') ?: url('/')), '/');
        return $baseUrl . '/api/v1/passport/auth/oauth/' . $driver . '/callback';
    }

    protected function getUserAgent(): string
    {
        return (string) admin_setting('app_name', config('app.name', 'Niceboard'));
    }

    protected function normalizeScene(?string $scene): string
    {
        return in_array($scene, ['login', 'register', 'bind'], true) ? $scene : 'login';
    }

    protected function isConfigured(array $provider): bool
    {
        return filled($provider['client_id']) && filled($provider['client_secret']);
    }

    protected function getProvider(string $driver): ?array
    {
        $providers = $this->getProviders();
        return $providers[$driver] ?? null;
    }

    protected function getProviders(): array
    {
        return [
            'google' => [
                'driver' => 'google',
                'label' => 'Google',
                'user_column' => 'google_id',
                'client_id' => $this->isEnabled('google_enabled') ? $this->getString('google_client_id') : null,
                'client_secret' => $this->isEnabled('google_enabled') ? $this->getString('google_client_secret') : null,
                'authorize_url' => 'https://accounts.google.com/o/oauth2/v2/auth',
                'token_url' => 'https://oauth2.googleapis.com/token',
                'userinfo_url' => 'https://openidconnect.googleapis.com/v1/userinfo',
                'scopes' => ['openid', 'email', 'profile'],
            ],
            'github' => [
                'driver' => 'github',
                'label' => 'GitHub',
                'user_column' => 'github_id',
                'client_id' => $this->isEnabled('github_enabled') ? $this->getString('github_client_id') : null,
                'client_secret' => $this->isEnabled('github_enabled') ? $this->getString('github_client_secret') : null,
                'authorize_url' => 'https://github.com/login/oauth/authorize',
                'token_url' => 'https://github.com/login/oauth/access_token',
                'userinfo_url' => 'https://api.github.com/user',
                'emails_url' => 'https://api.github.com/user/emails',
                'scopes' => ['read:user', 'user:email'],
            ],
            'linuxdo' => [
                'driver' => 'linuxdo',
                'label' => 'LinuxDO Connect',
                'user_column' => 'linuxdo_id',
                'client_id' => $this->isEnabled('linuxdo_enabled') ? $this->getString('linuxdo_client_id') : null,
                'client_secret' => $this->isEnabled('linuxdo_enabled') ? $this->getString('linuxdo_client_secret') : null,
                'authorize_url' => $this->getString('linuxdo_authorize_url') ?: 'https://connect.linux.do/oauth2/authorize',
                'token_url' => $this->getString('linuxdo_token_url') ?: 'https://connect.linux.do/oauth2/token',
                'userinfo_url' => $this->getString('linuxdo_userinfo_url') ?: 'https://connect.linux.do/api/user',
                'scopes' => ['openid', 'email', 'profile'],
            ],
        ];
    }

    protected function isEnabled(string $key): bool
    {
        $value = $this->config[$key] ?? false;

        return $value === true
            || $value === 1
            || $value === '1'
            || $value === 'true';
    }

    protected function getString(string $key): ?string
    {
        $value = trim((string) ($this->config[$key] ?? ''));

        return $value !== '' ? $value : null;
    }

    protected function getProviderRegisterMode(string $driver): string
    {
        return $this->getString($driver . '_register_mode') === 'bind_existing'
            ? 'bind_existing'
            : 'direct_register';
    }

    protected function getStateCacheKey(string $state): string
    {
        return 'PLUGIN_OAUTH_STATE_' . $state;
    }

    protected function getBindCacheKey(string $token): string
    {
        return 'PLUGIN_OAUTH_BIND_' . $token;
    }

    protected function getPendingRegisterCacheKey(string $token): string
    {
        return 'PLUGIN_OAUTH_PENDING_REGISTER_' . $token;
    }

    protected function getStateCookieName(string $state): string
    {
        return 'PLUGIN_OAUTH_STATE_' . $state;
    }
}
