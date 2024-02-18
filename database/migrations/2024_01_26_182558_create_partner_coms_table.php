<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('partner_coms', function (Blueprint $table) {
            $table->id();
            $table->string('partner_id');
            $table->string('school_id');
            $table->integer('amt');
            $table->string('time');
            $table->string('ref');
            $table->timestamps();

            // For queries based on partner_id
            $table->index('partner_id');
            // For queries based on school_id
            $table->index('school_id');
            // Index on 'amt' to make summing faster
            $table->index('amt');

        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('partner_coms');
    }
};
