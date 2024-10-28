<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Discount extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'discount_type',
        'value',
        'description',
    ];

    public function products()
    {
        return $this->belongsToMany(Product::class, 'productdiscount');
    }

}