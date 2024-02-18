<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class school_prop_data extends Model
{
    protected $table = 'school_prop_data';
    protected $primaryKey = 'user_id';
    public $incrementing = false;
    protected $fillable = [
         'user_id','fname','mname', 'lname', 'sex', 'phn', 'addr', 'eml'
    ];
    /*protected $hidden = [
        'password',
    ];*/
}
