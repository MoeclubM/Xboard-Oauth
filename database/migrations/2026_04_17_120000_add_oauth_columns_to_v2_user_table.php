<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::table('v2_user', function (Blueprint $table) {
            if (!Schema::hasColumn('v2_user', 'google_id')) {
                $table->string('google_id')->nullable()->after('telegram_id');
                $table->unique('google_id');
            }

            if (!Schema::hasColumn('v2_user', 'github_id')) {
                $table->string('github_id')->nullable()->after('google_id');
                $table->unique('github_id');
            }

            if (!Schema::hasColumn('v2_user', 'linuxdo_id')) {
                $table->string('linuxdo_id')->nullable()->after('github_id');
                $table->unique('linuxdo_id');
            }
        });
    }

    public function down(): void
    {
        Schema::table('v2_user', function (Blueprint $table) {
            if (Schema::hasColumn('v2_user', 'linuxdo_id')) {
                $table->dropUnique(['linuxdo_id']);
                $table->dropColumn('linuxdo_id');
            }

            if (Schema::hasColumn('v2_user', 'github_id')) {
                $table->dropUnique(['github_id']);
                $table->dropColumn('github_id');
            }

            if (Schema::hasColumn('v2_user', 'google_id')) {
                $table->dropUnique(['google_id']);
                $table->dropColumn('google_id');
            }
        });
    }
};
