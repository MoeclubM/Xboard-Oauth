<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        if (!Schema::hasTable('v2_user') || !Schema::hasColumn('v2_user', 'email')) {
            return;
        }

        Schema::table('v2_user', function (Blueprint $table) {
            $table->string('email', 191)->change();
        });
    }

    public function down(): void
    {
    }
};
