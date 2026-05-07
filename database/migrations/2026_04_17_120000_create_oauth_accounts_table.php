<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
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

        $this->importLegacyBindings();
    }

    public function down(): void
    {
        Schema::dropIfExists('v2_oauth_accounts');
    }

    private function importLegacyBindings(): void
    {
        foreach ([
            'google' => 'google_id',
            'github' => 'github_id',
            'linuxdo' => 'linuxdo_id',
        ] as $provider => $column) {
            if (!Schema::hasColumn('v2_user', $column)) {
                continue;
            }

            DB::table('v2_user')
                ->select(['id', 'email', $column])
                ->whereNotNull($column)
                ->where($column, '<>', '')
                ->orderBy('id')
                ->chunkById(500, function ($users) use ($provider, $column) {
                    $now = now();
                    $rows = [];

                    foreach ($users as $user) {
                        $rows[] = [
                            'user_id' => $user->id,
                            'provider' => $provider,
                            'provider_id' => (string) $user->{$column},
                            'email' => $user->email,
                            'created_at' => $now,
                            'updated_at' => $now,
                        ];
                    }

                    if ($rows) {
                        DB::table('v2_oauth_accounts')->insertOrIgnore($rows);
                    }
                });
        }
    }
};
