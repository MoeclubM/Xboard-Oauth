<?php

namespace Plugin\Oauth;

use App\Services\Plugin\AbstractPlugin;
use Plugin\Oauth\Services\OAuthService;

class Plugin extends AbstractPlugin
{
    public function boot(): void
    {
        $this->filter('guest_comm_config', function (array $data) {
            $data['oauth_providers'] = app(OAuthService::class)->getEnabledProviders();
            return $data;
        });
    }
}
