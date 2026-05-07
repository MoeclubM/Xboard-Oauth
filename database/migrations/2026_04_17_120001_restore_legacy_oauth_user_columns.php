<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (!Schema::hasTable('v2_user')) {
            return;
        }

        if (!$this->hasLegacyOAuthColumns()) {
            return;
        }

        $this->importLegacyBindings();
        $this->dropLegacyOAuthColumns();
    }

    public function down(): void
    {
    }

    private function hasLegacyOAuthColumns(): bool
    {
        foreach (['google_id', 'github_id', 'linuxdo_id'] as $column) {
            if (Schema::hasColumn('v2_user', $column)) {
                return true;
            }
        }

        return false;
    }

    private function importLegacyBindings(): void
    {
        if (!Schema::hasTable('v2_oauth_accounts')) {
            return;
        }

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

    private function dropLegacyOAuthColumns(): void
    {
        foreach (['linuxdo_id', 'github_id', 'google_id'] as $column) {
            if (!Schema::hasColumn('v2_user', $column)) {
                continue;
            }

            Schema::table('v2_user', function (Blueprint $table) use ($column) {
                $table->dropUnique([$column]);
                $table->dropColumn($column);
            });
        }
    }

};
