<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Mail\SSSMails;
use App\Models\admin_user;
use App\Models\announcements;
use App\Models\files;
use App\Models\partner_basic_data;
use App\Models\partner_coms;
use App\Models\partner_financial_data;
use App\Models\partner_general_data;
use App\Models\password_reset_tokens;
use App\Models\payment_refs;
use App\Models\school_basic_data;
use App\Models\school_general_data;
use App\Models\school_prop_data;
use Illuminate\Support\Facades\Log;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use App\Models\User;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Storage;
use Tymon\JWTAuth\Facades\JWTAuth;

/**
 * @OA\Info(
 *    title="SCHOOLSILO API | Stable Shield Solutions",
 *    version="1.0.0",
 *    description="Backend for the SCHOOLSILO project. Powered by Stable Shield Solutions",
 *    @OA\Contact(
 *        email="support@stableshield.com",
 *        name="API Support"
 *    ),
 *    @OA\License(
 *        name="Stable Shield API License",
 *        url="http://stableshield.com/api-licenses"
 *    )
 * )
 */


class ApiController extends Controller
{

    /**
     * @OA\Post(
     *     path="/api/setFirstAdminUserInfo",
     *     tags={"Unprotected"},
     *     summary="Create the admin, DO NOT CALL, YOU DONT NEED THIS ENDPOINT !!!!",
     *     @OA\Response(response="200", description="Login Successfully"),
     * )
     */
    public function setFirstAdminUserInfo(){
        User::create([
            "email"=> "admin@schoolsilo.cloud",
            "password"=> bcrypt("123456"),
        ]);
        admin_user::create([
            "email"=> 'admin@schoolsilo.cloud',
            "lname"=> 'SCHOOLSILO',
            "oname"=> 'ADMIN USER',
            "role"=> '0',
            "pd1"=> '1',
            "pd2"=> '1',
            "pw1"=> '1',
            "pw2"=> '1',
            "pp1"=> '1',
            "pp2"=> '1',
            "pm1"=> '1',
            "pm2"=> '1',
            
        ]);
        $token = JWTAuth::attempt([
            "email"=> "admin@schoolsilo.cloud",
            "password"=> "123456",
        ]);
        if(!empty($token)){
            return response()->json([
                "status"=> true,
                "message"=> "User created successfully",
                "token"=> $token
            ]);
        }
        // Respond
        return response()->json([
            "status"=> true,
            "message"=> "User created successfully",
        ]);
    }

    /**
     * @OA\Post(
     *     path="/api/registerSchool",
     *     tags={"Unprotected"},
     *     summary="Register a school",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="email", type="string", format="email"),
     *             @OA\Property(property="password", type="string"),
     *             @OA\Property(property="sname", type="string"),
     *             @OA\Property(property="phn", type="string"),
     *             @OA\Property(property="pcode", type="string"),
     *             @OA\Property(property="verif", type="string"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="Login Successfully"),
     * )
     */
    public function registerSchool(Request $request){
        //Data validation
        $request->validate([
            "email"=>"required|email",
            "password"=> "required",
            "sname"=> "required",
            "phn"=> "required",
            "pcode"=> "required",
            "verif"=> "required",
            "pay"=> "required",
        ]);
        $usr = User::where("email","=", $request->email)->first();
        if($usr){
            $usr->update([
                "password1"=>bcrypt($request->password),
            ]);
        }else{
            $usr = User::create([
                "email"=> $request->email,
                "password1"=> bcrypt($request->password),
            ]);
        }
        school_basic_data::create([
            "user_id"=> strval($usr->id),
            "sname"=> $request->sname,
            "phn"=> $request->phn,
            "pcode"=> $request->pcode,
            "eml"=> $request->email,
            "verif"=> $request->verif,
            "pay"=> $request->pay,
        ]);
        $token = JWTAuth::attempt([
            "email"=> $request->email,
            "password1"=> $request->password,
        ]);
        if(!empty($token)){
            return response()->json([
                "status"=> true,
                "message"=> "User created successfully: ".strval($usr->id),
                "token"=> $token,
                "pld"=>$usr
            ]);
        }
        // Respond
        return response()->json([
            "status"=> true,
            "message"=> "User created successfully",
            "pld"=>$usr
        ]);
    }


    /**
     * @OA\Post(
     *     path="/api/registerPartner",
     *     tags={"Unprotected"},
     *     summary="Register a partner",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="email", type="string", format="email"),
     *             @OA\Property(property="password", type="string"),
     *             @OA\Property(property="fname", type="string"),
     *             @OA\Property(property="mname", type="string", required=false),
     *             @OA\Property(property="lname", type="string"),
     * 
     *             @OA\Property(property="phn", type="string"),
     *             @OA\Property(property="pcode", type="string"),
     *             @OA\Property(property="verif", type="string"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="Login Successfully"),
     * )
     */
    public function registerPartner(Request $request){
        //Data validation
        $request->validate([
            "email"=>"required|email",
            "password"=> "required",
            "fname"=> "required",
            "lname"=> "required",
            "mname"=> "required",
            "phn"=> "required",
            "verif"=> "required",
        ]);
        $usr = User::where("email","=", $request->email)->first();
        if($usr){
            $usr->update([
                "password2"=>bcrypt($request->password),
            ]);
        }else{
            $usr = User::create([
                "email"=> $request->email,
                "password2"=> bcrypt($request->password),
            ]);
        }
        partner_basic_data::create([
            "user_id"=> strval($usr->id),
            "fname"=> $request->fname,
            "lname"=> $request->lname,
            "mname"=> $request->mname,
            "phn"=> $request->phn,
            "eml"=> $request->email,
            "verif"=> $request->verif,
        ]);
        $token = JWTAuth::attempt([
            "email"=> $request->email,
            "password1"=> $request->password,
        ]);
        if(!empty($token)){
            return response()->json([
                "status"=> true,
                "message"=> "User created successfully: ".strval($usr->id),
                "token"=> $token,
                "pld"=>$usr
            ]);
        }
        // Respond
        return response()->json([
            "status"=> true,
            "message"=> "User created successfully",
            "pld"=>$usr
        ]);
    }



    /**
     * @OA\Post(
     *     path="/api/sendPasswordResetEmail",
     *     tags={"Unprotected"},
     *     summary="Send reset email",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="email", type="string", format="email"),
     *             @OA\Property(property="type", type="string"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="Password reset token sent to mail"),
     * )
     */
    public function sendPasswordResetEmail(Request $request){
        //Data validation
        $request->validate([
            "email"=>"required",
            "type"=>"required",
        ]);
        $typeComment = $request->type == '0'? 'School':'Partner';
        $eml = $request->email;
        $pld = User::where("email","=", $eml)->first();
        if($pld){
            $token = Str::random(60); //Random reset token
            password_reset_tokens::updateOrCreate(
                ['email' => $eml],
                ['email' => $eml, 'token' => $token]
            );
            $data = [
                'name' => 'SCHOOLSILO USER',
                'subject' => '['.$typeComment.'] Reset your SCHOOLSILO password',
                'body' => 'Please go to this link to reset your password. It will expire in 1 hour:',
                'link'=>'https://portal.schoolsilo.cloud/passwordreset/'.$request->type.'/'.$token,
            ];
        
            Mail::to($eml)->send(new SSSMails($data));
            
            return response()->json([
                "status"=> true,
                "message"=> "Password reset token sent to mail",
            ]);   
        }
        // Respond
        return response()->json([
            "status"=> false,
            "message"=> "Email not found",
        ]);
    }


    /**
     * @OA\Post(
     *     path="/api/resetPassword",
     *     tags={"Unprotected"},
     *     summary="change user password",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="token", type="string"),
     *             @OA\Property(property="pwd", type="string"),
     *             @OA\Property(property="type", type="string"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="Password reset token sent to mail"),
     * )
     */
    public function resetPassword(Request $request){
        //Data validation
        $request->validate([
            "token"=>"required",
            "pwd"=>"required",
            "type"=>"required",
        ]);
        $pwdId = $request->type == '0'?'password1':'password2';
        $pld = password_reset_tokens::where("token","=", $request->token)->first();
        if($pld){
            $email = $pld->email;
            $usr = User::where("email","=", $email)->first();
            if($usr){
                $usr->update([
                    $pwdId=>bcrypt($request->pwd),
                ]);
                return response()->json([
                    "status"=> true,
                    "message"=> "Success. Please login again"
                ]);
            }
            return response()->json([
                "status"=> false,
                "message"=> "User not found",
            ]);   
        }
        return response()->json([
            "status"=> false,
            "message"=> "Denied. Invalid/Expired Token",
        ]);
    }

    /**
     * @OA\Post(
     *     path="/api/adminlogin",
     *     tags={"Unprotected"},
     *     summary="Login as admin",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="email", type="string", format="email"),
     *             @OA\Property(property="password", type="string"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="Login Successfully"),
     * )
     */
    public function adminlogin(Request $request){
        //Data validation
        $request->validate([
            "email"=>"required|email",
            "password"=> "required",
        ]);
        $user = User::where("email","=", $request->email)->first();
        $apld = admin_user::where("email","=", $user->email)->first();
        if($apld){
            $customClaims = [
                'role'=>$apld->role,
                'pd1' => $apld->pd1, 
                'pd2' => $apld->pd2, 
                'pw1' => $apld->pw1, 
                'pw2' => $apld->pw2, 
                'pp1' => $apld->pp1, 
                'pp2' => $apld->pp2, 
                'pm1' => $apld->pm1, 
                'pm2' => $apld->pm2, 
            ];
            $token = JWTAuth::customClaims($customClaims)->fromUser($user);
            return response()->json([
                "status"=> true,
                "message"=> "Admin authorization granted",
                "token"=> $token,
            ]);
        }
        return response()->json([
            "status"=> false,
            "message"=> "Invalid login details",
        ]);
    }


    /**
     * @OA\Post(
     *     path="/api/schoolLogin",
     *     tags={"Unprotected"},
     *     summary="School Login to the application",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="email", type="string", format="email"),
     *             @OA\Property(property="password", type="string"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="Login Successfully"),
     * )
     */
    public function schoolLogin(Request $request){
        //Data validation
        $request->validate([
            "email"=>"required|email",
            "password"=> "required",
        ]);
        $token = JWTAuth::attempt([
            "email"=> $request->email,
            "password1"=> $request->password,
        ]);
        if(!empty($token)){
            return response()->json([
                "status"=> true,
                "message"=> "User login successfully",
                "token"=> $token,
            ]);
        }
        // Respond
        return response()->json([
            "status"=> false,
            "message"=> "Invalid login details",
        ]);
    }

    /**
     * @OA\Post(
     *     path="/api/partnerLogin",
     *     tags={"Unprotected"},
     *     summary="Partner Login to the application",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="email", type="string", format="email"),
     *             @OA\Property(property="password", type="string"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="Login Successfully"),
     * )
     */
    public function partnerLogin(Request $request){
        //Data validation
        $request->validate([
            "email"=>"required|email",
            "password"=> "required",
        ]);
        $token = JWTAuth::attempt([
            "email"=> $request->email,
            "password2"=> $request->password,
        ]);
        if(!empty($token)){
            return response()->json([
                "status"=> true,
                "message"=> "User login successfully",
                "token"=> $token,
            ]);
        }
        // Respond
        return response()->json([
            "status"=> false,
            "message"=> "Invalid login details",
        ]);
    }


    //Paystack Webhook (POST, formdata)
    public function paystackConf(Request $request){ 
        $payload = json_decode($request->input('payload'), true);
        if($payload['event'] == "charge.success"){
            $ref = $payload['data']['reference'];
            $pld = payment_refs::where("ref","=", $ref)->first();
            if(Str::startsWith($ref,"schoolsilo-")){ //Its for US
                if(!$pld){ // Its unique
                    $payinfo = explode('-',$ref);
                    $amt = $payinfo[2];
                    $nm = $payload['data']['metadata']['name'];
                    $tm = $payload['data']['metadata']['time'];
                    payment_refs::create([
                        "ref"=> $ref,
                        "amt"=> $amt,
                        "time"=> $tm,
                    ]);
                    $upl = [
                        "diocese_id"=>$payinfo[3],
                        "ref"=> $ref,
                        "name"=> $nm,
                        "time"=> $tm,
                        "amt"=> intval($amt),
                    ];
                    /*if($payinfo[1]=='0'){
                        $yr = $payload['data']['metadata']['year'];
                        $upl['year'] = $yr;
                        pays0::create($upl);
                    }else{ // ie 1
                        $ev = $payload['data']['metadata']['event']; //Event ID
                        $upl['event'] = $ev;
                        pays1::create($upl);
                        //Create event_regs
                        event_regs::create([
                            'event_id' => $ev,
                            'diocese_id'=> $payinfo[3],
                            'proof'=> $ref,
                            'verif'=>'0'
                        ]);
                    }*/
                    Log::info('SUCCESS');
                }else{
                    Log::info('PLD EXISTS'.json_encode($pld));
                }
            }else{
                Log::info('STR BAD '.$ref);
            }
        }else{
            Log::info('EVENTS BAD '.$payload['event']);
        }
        return response()->json(['status' => 'success'], 200);
    }

    //---Protected from here



    /**
     * @OA\Post(
     *     path="/api/uploadFile",
     *     tags={"Api"},
     *     summary="Upload a file",
     *     security={{"bearerAuth": {}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="file", type="file"),
     *             @OA\Property(property="filename", type="string"),
     *             @OA\Property(property="folder", type="string"),
     *             @OA\Property(property="diocese_id", type="string"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="Success"),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function uploadFile(Request $request){
        $request->validate([
            'file' => 'required', //|mimes:jpeg,png,jpg,gif,svg|max:2048
            'filename' => 'required',
            'folder' => 'required',
            'diocese_id'=> 'required',
        ]);
        if ($request->hasFile('file')) {
            $file = $request->file('file');
            $filename = $request->filename;
            $folder = $request->folder;
            if (!Storage::disk('public')->exists($folder)) {
                // If it doesn't exist, create the directory
                Storage::disk('public')->makeDirectory($folder);
            }
            Storage::disk('public')->put($folder.'/'. $filename, file_get_contents($file));
            // Log It
            files::create([
                'diocese_id' => $request->diocese_id,
                'file'=> $filename,
                'folder'=> $folder,
            ]);
            return response()->json([
                "status"=> true,
                "message"=> "Success"
            ]);
        } else {
            return response()->json([
                "status"=> false,
                "message"=> "No file provided"
            ]);
        }
    }

    /**
     * @OA\Get(
     *     path="/api/getFiles/{diocese_id}",
     *     tags={"Api"},
     *     summary="Get all Files belonging to a diocese ",
     *     description="API: Use this endpoint to get all files by a diocese",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="diocese_id",
     *         in="path",
     *         required=true,
     *         description="Diocese ID",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(
     *          response="200",
     *          description="Success",
     *      ),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function getFiles($uid){
        $pld = files::where('diocese_id', $uid)->get();
        // Respond
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> $pld,
        ]);
    }

    /**
     * @OA\Get(
     *     path="/api/getFile/{folder}/{filename}",
     *     tags={"Api"},
     *     summary="Get File",
     *     description="API: Use this endpoint to get a file by providing the folder and filename as path parameters.",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="folder",
     *         in="path",
     *         required=true,
     *         description="Name of the folder",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Parameter(
     *         name="filename",
     *         in="path",
     *         required=true,
     *         description="Name of the file",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(
     *          response="200",
     *          description="Success",
     *          @OA\MediaType(
     *              mediaType="application/octet-stream",
     *              @OA\Schema(type="file")
     *          )
     *      ),
     *     @OA\Response(response="401", description="Unauthorized"),
     *     @OA\Response(response="404", description="File not found"),
     * )
     */
    public function getFile($folder,$filename){
        if (Storage::disk('public')->exists($folder.'/'.$filename)) {
            return response()->file(Storage::disk('public')->path($folder.'/'.$filename));
        } else {
            return response()->json([
                "status" => false,
                "message" => "File not found",
            ], 404);
        }
    }

    

    /**
     * @OA\Get(
     *     path="/api/fileExists/{folder}/{filename}",
     *     tags={"Api"},
     *     summary="Check if File Exists",
     *     description="API: Use this endpoint to check if a file exists by providing the folder and filename as path parameters.",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="folder",
     *         in="path",
     *         required=true,
     *         description="Name of the folder",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Parameter(
     *         name="filename",
     *         in="path",
     *         required=true,
     *         description="Name of the file",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function fileExists($folder,$filename){
        if (Storage::disk('public')->exists($folder.'/'.$filename)) {
            return response()->json([
                "status" => true,
                "message" => "Yes, it does",
            ]);
        } else {
            return response()->json([
                "status" => false,
                "message" => "File not found",
            ]);
        }
    }

    /**
     * @OA\Post(
     *     path="/api/setSchoolBasicInfo",
     *     tags={"Api"},
     *     summary="Set School Basic Info",
     *     description="This sensitive endpoint is used to set basic information about a school.",
     *     security={{"bearerAuth": {}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="user_id", type="string"),
     *             @OA\Property(property="email", type="string", format="email"),
     *             @OA\Property(property="sname", type="string"),
     *             @OA\Property(property="phn", type="string"),
     *             @OA\Property(property="pcode", type="string"),
     *             @OA\Property(property="verif", type="string"),
     *             @OA\Property(property="pay", type="string"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="Success"),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function setSchoolBasicInfo(Request $request){
        $request->validate([
            "user_id"=>"required",
            "sname"=> "required",
            "phn"=> "required",
            "email"=> "required",
            "pcode"=> "required",
            "verif"=> "required",
            "pay"=> "required",
        ]);
        $dbd = school_basic_data::where("user_id", $request->user_id)->first();
        if($dbd){
            $dbd->update([
                "sname"=> $request->sname,
                "phn"=> $request->phn,
                "pcode"=> $request->pcode,
                "eml"=> $request->email,
                "verif"=> $request->verif,
                "pay"=> $request->pay,
            ]);
            return response()->json([
                "status"=> true,
                "message"=> "Success"
            ]);
        }
        return response()->json([
            "status"=> false,
            "message"=> "School not found"
        ]);
    }


    /**
     * @OA\Get(
     *     path="/api/getSchoolBasicInfo/{uid}",
     *     tags={"Api"},
     *     summary="Get School Basic Info",
     *     description="Use this endpoint to get basic information about a school.",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="uid",
     *         in="path",
     *         required=true,
     *         description="User Id of the School",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function getSchoolBasicInfo($uid){
        $pld = school_basic_data::where("user_id", $uid)->first();
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> $pld,
        ]);
    }


    
    /**
     * @OA\Post(
     *     path="/api/setPartnerBasicInfo",
     *     tags={"Api"},
     *     summary="Set Partner Basic Info",
     *     description="This endpoint is used to set basic information about a partner.",
     *     security={{"bearerAuth": {}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="user_id", type="string"),
     *             @OA\Property(property="email", type="string", format="email"),
     *             @OA\Property(property="fname", type="string"),
     *             @OA\Property(property="mname", type="string"),
     *             @OA\Property(property="lname", type="string"),
     *             @OA\Property(property="phn", type="string"),
     *             @OA\Property(property="verif", type="string"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="Success"),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function setPartnerBasicInfo(Request $request){
        $request->validate([
            "user_id"=>"required",
            "fname"=> "required",
            "mname"=> "required",
            "lname"=> "required",
            "phn"=> "required",
            "email"=> "required",
            "verif"=> "required",
        ]);
        $dbd = school_basic_data::where("user_id", $request->user_id)->first();
        if($dbd){
            $dbd->update([
                "user_id"=> $request->user_id,
                "fname"=> $request->fname,
                "lname"=> $request->lname,
                "mname"=> $request->mname,
                "phn"=> $request->phn,
                "eml"=> $request->email,
                "verif"=> $request->verif,
            ]);
            return response()->json([
                "status"=> true,
                "message"=> "Success"
            ]);
        }
        return response()->json([
            "status"=> false,
            "message"=> "Partner not found"
        ]);
    }


    /**
     * @OA\Get(
     *     path="/api/getPartnerBasicInfo/{uid}",
     *     tags={"Api"},
     *     summary="Get Partner Basic Info",
     *     description="Use this endpoint to get basic information about a partner.",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="uid",
     *         in="path",
     *         required=true,
     *         description="User Id of the Partner",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function getPartnerBasicInfo($uid){
        $pld = partner_basic_data::where("user_id", $uid)->first();
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> $pld,
        ]);
    }



    /**
     * @OA\Post(
     *     path="/api/setSchoolGeneralInfo",
     *     tags={"Api"},
     *     summary="Set School General Info",
     *     description="Use this endpoint to set general information about a school.",
     *     security={{"bearerAuth": {}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="user_id", type="string", description="The user ID"),
     *             @OA\Property(property="state", type="string", description="State"),
     *             @OA\Property(property="lga", type="string", description="Local Government Area"),
     *             @OA\Property(property="addr", type="string", description="Address"),
     *             @OA\Property(property="vision", type="string", description="Vision"),
     *             @OA\Property(property="mission", type="string", description="Mission"),
     *             @OA\Property(property="values", type="string", description="Values"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="success"),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function setSchoolGeneralInfo(Request $request){
        $request->validate([
            "user_id"=>"required",
            "state"=> "required",
            "lga"=> "required",
            "addr"=> "required",
            "vision"=> "required",
            "mission"=> "required",
            "values"=> "required",
        ]);
        school_general_data::updateOrCreate(
            ["user_id"=> $request->user_id,],
            [
            "state"=> $request->state,
            "lga"=> $request->lga,
            "addr"=> $request->addr,
            "vision"=> $request->vision,
            "mission"=> $request->mission,
            "values"=> $request->values,
        ]);
        // Respond
        return response()->json([
            "status"=> true,
            "message"=> "Success"
        ]);
    }

    /**
     * @OA\Get(
     *     path="/api/getSchoolGeneralInfo/{uid}",
     *     tags={"Api"},
     *     summary="Get School General Info",
     *     description="Use this endpoint to get general information about a school.",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="uid",
     *         in="path",
     *         required=true,
     *         description="User Id",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function getSchoolGeneralInfo($uid){
        $pld = school_general_data::where("user_id", $uid)->first();
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> $pld,
        ]);
    }


     /**
     * @OA\Post(
     *     path="/api/setSchoolPropInfo",
     *     tags={"Api"},
     *     summary="Set School Proprietor Info",
     *     description="Use this endpoint to set proprietor information about a school.",
     *     security={{"bearerAuth": {}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="user_id", type="string", description="The user ID"),
     *             @OA\Property(property="fname", type="string", description="First Name"),
     *              @OA\Property(property="mname", type="string", description="Middle Name"),
     *              @OA\Property(property="lname", type="string", description="Last Name"),
     *             @OA\Property(property="sex", type="string", description="Gender"),
     *             @OA\Property(property="phn", type="string", description="Phone"),
     *             @OA\Property(property="addr", type="string", description="Address"),
     *             @OA\Property(property="email", type="string", description="Email", format="email"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="success"),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function setSchoolPropInfo(Request $request){
        $request->validate([
            "user_id"=>"required",
            "fname"=> "required",
            "mname"=> "required",
            "lname"=> "required",
            "sex"=> "required",
            "phn"=> "required",
            "addr"=> "required",
            "email"=> "required|email",
        ]);
        school_prop_data::updateOrCreate(
            ["user_id"=> $request->user_id,],
            [
            "fname"=> $request->fname,
            "mname"=> $request->mname,
            "lname"=> $request->lname,
            "sex"=> $request->sex,
            "phn"=> $request->phn,
            "addr"=> $request->addr,
            "eml"=> $request->email,
        ]);
        // Respond
        return response()->json([
            "status"=> true,
            "message"=> "Success"
        ]);
    }

    /**
     * @OA\Get(
     *     path="/api/getSchoolPropInfo/{uid}",
     *     tags={"Api"},
     *     summary="Get School Proprietor Info",
     *     description="Use this endpoint to get general information about a proprietor.",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="uid",
     *         in="path",
     *         required=true,
     *         description="User Id",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function getSchoolPropInfo($uid){
        $pld = school_prop_data::where("user_id", $uid)->first();
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> $pld,
        ]);
    }


    /**
     * @OA\Post(
     *     path="/api/setPartnerGeneralInfo",
     *     tags={"Api"},
     *     summary="Set Partner General Info",
     *     description="Use this endpoint to set general information about a partner.",
     *     security={{"bearerAuth": {}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="user_id", type="string", description="The user ID"),
     *             @OA\Property(property="state", type="string", description="State"),
     *             @OA\Property(property="lga", type="string", description="Local Government Area"),
     *             @OA\Property(property="addr", type="string", description="Address"),
     *             @OA\Property(property="sex", type="string", description="Vision"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="success"),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function setPartnerGeneralInfo(Request $request){
        $request->validate([
            "user_id"=>"required",
            "state"=> "required",
            "lga"=> "required",
            "addr"=> "required",
            "sex"=> "required",
        ]);
        partner_general_data::updateOrCreate(
            ["user_id"=> $request->user_id,],
            [
            "state"=> $request->state,
            "lga"=> $request->lga,
            "addr"=> $request->addr,
            "sex"=> $request->sex,
        ]);
        // Respond
        return response()->json([
            "status"=> true,
            "message"=> "Success"
        ]);
    }

    /**
     * @OA\Get(
     *     path="/api/getPartnerGeneralInfo/{uid}",
     *     tags={"Api"},
     *     summary="Get Partner General Info",
     *     description="Use this endpoint to get general information about a partner.",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="uid",
     *         in="path",
     *         required=true,
     *         description="User Id",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function getPartnerGeneralInfo($uid){
        $pld = partner_general_data::where("user_id", $uid)->first();
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> $pld,
        ]);
    }


    /**
     * @OA\Post(
     *     path="/api/setPartnerFinancialInfo",
     *     tags={"Api"},
     *     summary="Set Partner Financial Info",
     *     description="Use this endpoint to set financial information about a partner.",
     *     security={{"bearerAuth": {}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="user_id", type="string", description="The user ID"),
     *             @OA\Property(property="bnk", type="string", description="Bank Code"),
     *             @OA\Property(property="anum", type="string", description="Account Number"),
     *             @OA\Property(property="aname", type="string", description="Acct Name"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="success"),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function setPartnerFinancialInfo(Request $request){
        $request->validate([
            "user_id"=>"required",
            "bnk"=> "required",
            "anum"=> "required",
            "aname"=> "required",
        ]);
        partner_financial_data::updateOrCreate(
            ["user_id"=> $request->user_id,],
            [
            "bnk"=> $request->state,
            "anum"=> $request->anum,
            "aname"=> $request->aname,
        ]);
        // Respond
        return response()->json([
            "status"=> true,
            "message"=> "Success"
        ]);
    }

    /**
     * @OA\Get(
     *     path="/api/getPartnerFinancialInfo/{uid}",
     *     tags={"Api"},
     *     summary="Get Partner Fiancial Info",
     *     description="Use this endpoint to get financial information about a partner.",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="uid",
     *         in="path",
     *         required=true,
     *         description="User Id",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function getPartnerFinancialInfo($uid){
        $pld = partner_financial_data::where("user_id", $uid)->first();
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> $pld,
        ]); 
    }

    /**
     * @OA\Get(
     *     path="/api/getPartnerComs/{uid}",
     *     tags={"Api"},
     *     summary="Get Partner Commissions",
     *     description="Use this endpoint to get information about a Partner Commissions.",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="uid",
     *         in="path",
     *         required=true,
     *         description="User ID of the partner",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Parameter(
     *         name="start",
     *         in="query",
     *         required=false,
     *         description="Index to start at",
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Parameter(
     *         name="count",
     *         in="query",
     *         required=false,
     *         description="No of records to retrieve",
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function getPartnerComs($uid){
        $start = 0;
        $count = 20;
        if(request()->has('start') && request()->has('count')) {
            $start = request()->input('start');
            $count = request()->input('count');
        }
        $pld = partner_coms::where('partner_id',$uid)->skip($start)->take($count)->get();
        // Respond
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> $pld,
        ]);
    }

    /**
     * @OA\Get(
     *     path="/api/getPartnerComsBySchool/{uid}/{sid}",
     *     tags={"Api"},
     *     summary="Get Partner Commissions by School",
     *     description="Use this endpoint to get information about a Partner Commissions by School.",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="uid",
     *         in="path",
     *         required=true,
     *         description="User ID of the partner",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Parameter(
     *         name="sid",
     *         in="path",
     *         required=true,
     *         description="User ID of the school",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Parameter(
     *         name="start",
     *         in="query",
     *         required=false,
     *         description="Index to start at",
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Parameter(
     *         name="count",
     *         in="query",
     *         required=false,
     *         description="No of records to retrieve",
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function getPartnerComsBySchool($uid,$sid){
        $start = 0;
        $count = 20;
        if(request()->has('start') && request()->has('count')) {
            $start = request()->input('start');
            $count = request()->input('count');
        }
        $pld = partner_coms::where('partner_id',$uid)->where('school_id',$sid)->skip($start)->take($count)->get();
        // Respond
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> $pld,
        ]);
    }

    /**
     * @OA\Get(
     *     path="/api/getPartnerHighlights/{uid}",
     *     tags={"Api"},
     *     summary="Get Highlights (Partner)",
     *     description=" Use this endpoint to get partner highlights.",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="uid",
     *         in="path",
     *         required=true,
     *         description="User ID of the partner",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function getPartnerHighlights($uid){
        $totalSchools = school_basic_data::where('pcode',$uid)->count();
        $totalComs = partner_coms::where('partner_id',$uid)->sum('amt');
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> [
                'totalSchools'=>$totalSchools,
                'totalComs'=>$totalComs
            ],
        ]);   
    }

    
    /**
     * @OA\Get(
     *     path="/api/getAnnouncements",
     *     tags={"Api"},
     *     summary="Get Announcements",
     *     description="Use this endpoint to get information about announcements.",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="start",
     *         in="query",
     *         required=false,
     *         description="Index to start at",
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Parameter(
     *         name="count",
     *         in="query",
     *         required=false,
     *         description="No of records to retrieve",
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function getAnnouncements(){
        $start = 0;
        $count = 5;
        if(request()->has('start') && request()->has('count')) {
            $start = request()->input('start');
            $count = request()->input('count');
        }
        $pld = announcements::take($count)->skip($start)->get();
        // Respond
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> $pld,
        ]);
    }




    


    //--------------- ADMIN CODES

     /**
     * @OA\Post(
     *     path="/api/setAnnouncements",
     *     tags={"Admin"},
     *     summary="Create Announcement",
     *     description="ADMIN: Use this endpoint to create an announcement.",
     *     security={{"bearerAuth": {}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="title", type="string", description="Title of the announcement"),
     *             @OA\Property(property="msg", type="string", description="Message content of the announcement"),
     *             @OA\Property(property="time", type="string", description="Time of the announcement"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="Announcement created successfully"),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function setAnnouncements(Request $request){
        if ( $this->hasRole('0')) {
              $request->validate([
                "title"=>"required",
                "msg"=> "required",
                "time"=> "required",
            ]);
            announcements::create([
                "title"=> $request->title,
                "msg"=> $request->msg,
                "time"=> $request->time,
            ]);
            // Respond
            return response()->json([
                "status"=> true,
                "message"=> "Announcement Added"
            ]);
        }
        return response()->json([
            "status"=> false,
            "message"=> "Access denied"
        ],401);
    }



    //------------------------------------

    //Refresh Token API (GET)
    public function refreshToken(){
        $newToken = auth()->refresh();
        return response()->json([
            "status"=> true,
            "message"=> "New token generated",
            "token"=> $newToken,
        ]);
    }

    /**
     * @OA\Get(
     *     path="/api/checkTokenValidity",
     *     tags={"Api"},
     *     summary="Check if user is still logged in",
     *     description="No params needed except bearer token. If you get a 200, the token is still valid",
     *     security={{"bearerAuth": {}}},
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function checkTokenValidity()
    {
        return response()->json([
            "status"=> true,
            "message"=> "Token OK",
        ]);
    }

    //Logout API (GET)
    public function logout(){
        auth()->logout();
        return response()->json([
            "status"=> true,
            "message"=> "Logout successful",
        ]);
    }

    //---NON ENDPOINTS

    public function permOk($pid): bool
    {
        // $pp = auth()->payload()->get($pid);
        // return $pp!=null  && $pp=='1';
        return true;
    }

    public function hasRole($rid): bool
    {
        // $role = auth()->payload()->get('role');
        // return $role!=null  && $role==$rid;
        return true;
    }

}
