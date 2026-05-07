<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('v2_oauth_accounts', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id')->index();
            $table->string('provider', 32);
            $table->string('provider_id', 191);
            $table->string('email', 191)->nullable();
            $table->timestamps();

            $table->unique(['provider', 'provider_id'], 'v2_oauth_accounts_provider_id_unique');
            $table->unique(['user_id', 'provider'], 'v2_oauth_accounts_user_provider_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('v2_oauth_accounts');
    }
};
