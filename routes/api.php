<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\ApiController;


/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

// API Routes PREFIX = api

// -- OPEN

Route::post('registerSchool', [ApiController::class,'registerSchool']);
Route::post('registerPartner', [ApiController::class,'registerPartner']);
Route::post('schoolLogin', [ApiController::class,'schoolLogin']);
Route::post('partnerLogin', [ApiController::class,'partnerLogin']);
Route::post('adminLogin', [ApiController::class,'adminLogin']);
Route::post('setFirstAdminUserInfo', [ApiController::class,'setFirstAdminUserInfo']); // For first Admin (call on postman)
Route::post('paystackConf', [ApiController::class,'paystackConf']);
Route::post('sendPasswordResetEmail', [ApiController::class,'sendPasswordResetEmail']);
Route::post('resetPassword', [ApiController::class,'resetPassword']);

Route::get('getFile/{folder}/{filename}', [ApiController::class, 'getFile']);

// - PROTECTED

Route::group([
    'middleware'=> ['auth:api'],
], function(){

    Route::post('setSchoolBasicInfo', [ApiController::class,'setSchoolBasicInfo']);
    Route::post('setPartnerBasicInfo', [ApiController::class,'setPartnerBasicInfo']);
    Route::post('setSchoolGeneralInfo', [ApiController::class,'setSchoolGeneralInfo']);
    Route::post('setPartnerGeneralInfo', [ApiController::class,'setPartnerGeneralInfo']);
    Route::post('setSchoolPropInfo', [ApiController::class,'setSchoolPropInfo']);
    Route::post('setPartnerFinancialInfo', [ApiController::class,'setPartnerFinancialInfo']);

    
    Route::get('getSchoolBasicInfo/{uid}', [ApiController::class, 'getSchoolBasicInfo']);
    Route::get('getPartnerBasicInfo/{uid}', [ApiController::class, 'getPartnerBasicInfo']);
    Route::get('getSchoolGeneralInfo/{uid}', [ApiController::class, 'getSchoolGeneralInfo']);
    Route::get('getPartnerGeneralInfo/{uid}', [ApiController::class, 'getPartnerGeneralInfo']);
    Route::get('getSchoolPropInfo/{uid}', [ApiController::class, 'getSchoolPropInfo']);
    Route::get('getPartnerHighlights/{uid}', [ApiController::class, 'getPartnerHighlights']);
    Route::get('getPartnerFinancialInfo/{uid}', [ApiController::class, 'getPartnerFinancialInfo']);
    Route::get('getPartnerComs/{uid}', [ApiController::class, 'getPartnerComs']);
    Route::get('getPartnerComsBySchool/{uid}/{sid}', [ApiController::class, 'getPartnerComsBySchool']);
    Route::get('getAnnouncements', [ApiController::class, 'getAnnouncements']);
    Route::get('getSchoolsByPartner/{uid}', [ApiController::class, 'getSchoolsByPartner']);
    Route::get('searchSchools', [ApiController::class, 'searchSchools']);
    Route::get('searchPartners', [ApiController::class, 'searchPartners']);


    Route::post('uploadFile', [ApiController::class,'uploadFile']);

    Route::get('fileExists/{folder}/{filename}', [ApiController::class, 'fileExists']);
    Route::get('getFiles/{uid}', [ApiController::class, 'getFiles']);

    //---- ADMIN ONLY
    Route::post('setAnnouncements', [ApiController::class,'setAnnouncements']);
    Route::post('sendMail', [ApiController::class,'sendMail']);
    Route::post('setSchoolsiloInfo', [ApiController::class,'setSchoolsiloInfo']);
    Route::post('setAdmin', [ApiController::class,'setAdmin']);

    Route::get('getAdminHighlights', [ApiController::class, 'getAdminHighlights']);
    Route::get('getAdmin', [ApiController::class, 'getAdmin']);
    Route::get('getSchoolsByV/{vid}', [ApiController::class, 'getSchoolsByV']);
    Route::get('getPartnersByV/{vid}', [ApiController::class, 'getPartnersByV']);
    Route::get('getVerificationStats', [ApiController::class, 'getVerificationStats']);
    Route::get('getPaymentStats', [ApiController::class, 'getPaymentStats']);
    Route::get('getSchoolsByPay/{pid}', [ApiController::class, 'getSchoolsByPay']);
    Route::get('getSchoolsiloInfo/{uid}', [ApiController::class, 'getSchoolsiloInfo']);
    Route::get('getAdmins', [ApiController::class, 'getAdmins']);
    Route::get('removeAdmin', [ApiController::class, 'removeAdmin']);

    //--MESSAGES
    Route::post('createMsgThread', [ApiController::class,'createMsgThread']);
    Route::post('sendMsg', [ApiController::class,'sendMsg']);

    Route::get('getMyMessages/{uid}', [ApiController::class, 'getMyMessages']);
    Route::get('getMessageThread/{tid}', [ApiController::class, 'getMessageThread']);
    Route::get('getMyMessagesStat/{tid}', [ApiController::class, 'getMyMessagesStat']);
    Route::get('searchMsgThread', [ApiController::class, 'searchMsgThread']);



    


    //----

    
    Route::get('refresh', [ApiController::class,'refreshToken']);
    Route::get('logout', [ApiController::class,'logout']);
    Route::get('checkTokenValidity', [ApiController::class,'checkTokenValidity']);
    
});
