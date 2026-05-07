<?php

namespace Plugin\Oauth\Models;

use Illuminate\Database\Eloquent\Model;

class OAuthAccount extends Model
{
    protected $table = 'v2_oauth_accounts';
    protected $guarded = ['id'];
}
