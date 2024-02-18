<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class partner_coms extends Model
{
    protected $table = 'partner_coms';
    protected $fillable = [
        'partner_id','school_id','amt','time', 'ref'
    ];
    /*protected $hidden = [
        'password',
    ];*/
}
