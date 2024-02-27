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
        Schema::create('msgthread', function (Blueprint $table) {
            $table->id();
            $table->string('from');
            $table->string('from_uid');
            $table->string('to');
            $table->string('to_uid');
            $table->string('last_msg');
            $table->timestamps();

             // For queries based on from_uid
             $table->index('from_uid');
             // For queries based on to_uid
             $table->index('to_uid');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('msgthread');
    }
};
