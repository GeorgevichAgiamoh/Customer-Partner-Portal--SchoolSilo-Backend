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
        Schema::create('school_prop_data', function (Blueprint $table) {
            $table->string('user_id')->primary();
            $table->string('fname');
            $table->string('mname');
            $table->string('lname');
            $table->string('sex');
            $table->string('phn');
            $table->text('addr');
            $table->string('eml');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('school_prop_data');
    }
};
