<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class schoolsilo_info extends Model
{
    protected $table = 'schoolsilo_info'; 
    protected $primaryKey = 'user_id';
    public $incrementing = false;
    protected $fillable = [
        'user_id','cname', 'regno', 'addr','nationality', 'state','lga','aname', 'anum','bnk','pname','peml','pphn','paddr'
    ];
    /*protected $hidden = [
        'password',
    ];*/
}
