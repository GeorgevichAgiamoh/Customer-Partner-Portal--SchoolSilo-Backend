<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
use Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Authenticatable implements JWTSubject
{
    use HasApiTokens, HasFactory, Notifiable;
    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'email',
        'password1',
        'password2',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password1',
        'password2',
        'remember_token',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
    ];

    /**
     * Mutator for hashing the first password.
     *
     * @param string $value
     * @return void
     */
    public function setPassword1Attribute($value)
    {
        $this->attributes['password1'] = bcrypt($value);
    }

    /**
     * Mutator for hashing the second password.
     *
     * @param string $value
     * @return void
     */
    public function setPassword2Attribute($value)
    {
        $this->attributes['password2'] = bcrypt($value);
    }

    /**
     * Accessor for getting the first password.
     *
     * @param string $value
     * @return string
     */
    public function getPassword1Attribute($value)
    {
        return decrypt($value);
    }

    /**
     * Accessor for getting the second password.
     *
     * @param string $value
     * @return string
     */
    public function getPassword2Attribute($value)
    {
        return decrypt($value);
    }
    
    public function getJWTIdentifier(){
        return $this->getKey();
    }

    public function getJWTCustomClaims(){
        return [];
    }


}
