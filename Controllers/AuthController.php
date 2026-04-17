<?php

namespace Plugin\Oauth\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Plugin\Oauth\Services\OAuthService;

class AuthController extends Controller
{
    public function __construct(protected OAuthService $oauthService)
    {
    }

    public function redirect(string $driver, Request $request)
    {
        return $this->oauthService->redirect($driver, $request);
    }

    public function callback(string $driver, Request $request)
    {
        return $this->oauthService->callback($driver, $request);
    }

    public function bindings(Request $request)
    {
        return $this->success($this->oauthService->getUserBindings($request->user()));
    }

    public function prepareBind(string $driver, Request $request)
    {
        [$success, $result] = $this->oauthService->prepareBind($driver, $request->user());
        if (!$success) {
            return $this->fail($result);
        }

        return $this->success($result);
    }

    public function unbind(string $driver, Request $request)
    {
        [$success, $result] = $this->oauthService->unbind($driver, $request->user());
        if (!$success) {
            return $this->fail($result);
        }

        return $this->success($result);
    }
}
