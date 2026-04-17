<?php

use Illuminate\Support\Facades\Route;
use Plugin\Oauth\Controllers\AuthController;

Route::prefix('api/v1/passport')->group(function () {
    Route::get('/auth/oauth/{driver}/redirect', [AuthController::class, 'redirect']);
    Route::get('/auth/oauth/{driver}/callback', [AuthController::class, 'callback']);
});

Route::prefix('api/v1/user')->middleware('user')->group(function () {
    Route::get('/oauth/bindings', [AuthController::class, 'bindings']);
    Route::post('/oauth/{driver}/bind', [AuthController::class, 'prepareBind']);
    Route::post('/oauth/{driver}/unbind', [AuthController::class, 'unbind']);
});

Route::prefix('api/v2/passport')->group(function () {
    Route::get('/auth/oauth/{driver}/redirect', [AuthController::class, 'redirect']);
    Route::get('/auth/oauth/{driver}/callback', [AuthController::class, 'callback']);
});

Route::prefix('api/v2/user')->middleware('user')->group(function () {
    Route::get('/oauth/bindings', [AuthController::class, 'bindings']);
    Route::post('/oauth/{driver}/bind', [AuthController::class, 'prepareBind']);
    Route::post('/oauth/{driver}/unbind', [AuthController::class, 'unbind']);
});
