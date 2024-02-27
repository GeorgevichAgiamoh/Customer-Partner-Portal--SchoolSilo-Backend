<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Mail\SSSMails;
use App\Models\admin_user;
use App\Models\announcements;
use App\Models\files;
use App\Models\msg;
use App\Models\msgthread;
use App\Models\partner_basic_data;
use App\Models\partner_coms;
use App\Models\partner_financial_data;
use App\Models\partner_general_data;
use App\Models\password_reset_tokens;
use App\Models\payment_refs;
use App\Models\school_basic_data;
use App\Models\school_general_data;
use App\Models\school_prop_data;
use App\Models\schoolsilo_info;
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
     *     summary="Create the admin, MUST CALL WITH ADMIN UID !!!",
     *     @OA\Response(response="200", description="SUccess"),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="uid", type="string"),
     *         )
     *     ),
     * )
     */
    public function setFirstAdminUserInfo(Request $request){
        $request->validate([
            "uid"=>"required",
        ]);
        admin_user::create([
            "user_id"=> $request->uid,
            "lname"=> 'SCHOOLSILO',
            "oname"=> 'ADMIN USER',
            "role"=> '0',
            "pd1"=> '1',
            "pd2"=> '1',
            "pp1"=> '1',
            "pp2"=> '1',
            "pm1"=> '1',
            "pm2"=> '1',
        ]);
        return response()->json([
            "status"=> true,
            "message"=> "User created successfully",
        ]);
    }

    
    /**
     * @OA\Post(
     *     path="/api/registerAdmin",
     *     tags={"Unprotected"},
     *     summary="Register an admin",
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
    public function registerAdmin(Request $request){
        //Data validation
        $request->validate([
            "email"=>"required|email",
            "password"=> "required",
        ]);
        $uid = $request->email.'a';
        $usr = User::where("uid", $uid)->first();
        if(!$usr){
            $usr = User::create([
                "email"=> $request->email,
                "uid"=> $uid,
                "password"=> bcrypt($request->password),
            ]);
            $token = JWTAuth::attempt([
                "email"=> $request->email,
                "password"=> $request->password,
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
        return response()->json([
            "status"=> false,
            "message"=> "Account already exists",
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
        $uid = $request->email.'s';
        $usr = User::where("uid", $uid)->first();
        if(!$usr){
            $usr = User::create([
                "email"=> $request->email,
                "uid"=> $uid,
                "password"=> bcrypt($request->password),
            ]);
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
                "password"=> $request->password,
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
        return response()->json([
            "status"=> false,
            "message"=> "Account already exists",
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
     *             @OA\Property(property="mname", type="string"),
     *             @OA\Property(property="lname", type="string"),
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
        $uid = $request->email.'p';
        $usr = User::where("uid", $uid)->first();
        if(!$usr){
            $usr = User::create([
                "email"=> $request->email,
                "uid"=> $uid,
                "password"=> bcrypt($request->password),
            ]);
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
                "password"=> $request->password,
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
        return response()->json([
            "status"=> false,
            "message"=> "Account already exists",
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
        $pld = password_reset_tokens::where("token","=", $request->token)->first();
        if($pld){
            $email = $pld->email;
            $uid = $email.($request->type == '0'?'s':'p');
            $usr = User::where("uid", $uid)->first();
            if($usr){
                $usr->update([
                    "password"=>bcrypt($request->pwd),
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
     *     path="/api/adminLogin",
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
    public function adminLogin(Request $request){
        //Data validation
        $request->validate([
            "email"=>"required|email",
            "password"=> "required",
        ]);
        $uid = $request->email.'a';
        $usr = User::where("uid", $uid)->first();
        if($usr){
            $apld = admin_user::where("user_id","=", $usr->id)->first();
            if($apld){
                $customClaims = [
                    'role'=>$apld->role,
                    'pd1' => $apld->pd1, 
                    'pd2' => $apld->pd2, 
                    'pp1' => $apld->pp1, 
                    'pp2' => $apld->pp2, 
                    'pm1' => $apld->pm1, 
                    'pm2' => $apld->pm2, 
                ];
                $token = JWTAuth::customClaims($customClaims)->fromUser($usr);
                return response()->json([
                    "status"=> true,
                    "message"=> "Admin authorization granted",
                    "token"=> $token,
                    "pld"=>$usr
                ]);
            }
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
            "password"=> $request->password,
        ]);
        $uid = $request->email.'s';
        $usr = User::where("uid", $uid)->first();
        if(!empty($token) && $usr){
            return response()->json([
                "status"=> true,
                "message"=> "User login successfully",
                "token"=> $token,
                "pld"=>$usr
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
            "password"=> $request->password,
        ]);
        $uid = $request->email.'p';
        $usr = User::where("uid", $uid)->first();
        if(!empty($token) && $usr){
            return response()->json([
                "status"=> true,
                "message"=> "User login successfully",
                "token"=> $token,
                "pld"=>$usr
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
                    if($payinfo[1]=='0'){
                        school_basic_data::where("user_id", $payinfo[3])->update(['pay' => '1']);
                    }
                    /*
                    $upl = [
                        "diocese_id"=>$payinfo[3],
                        "ref"=> $ref,
                        "name"=> $nm,
                        "time"=> $tm,
                        "amt"=> intval($amt),
                    ];
                    if($payinfo[1]=='0'){
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
     *             @OA\Property(property="user_id", type="string"),
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
            'user_id'=> 'required',
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
                'user_id' => $request->user_id,
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
     *     path="/api/getFiles/{user_id}",
     *     tags={"Api"},
     *     summary="Get all Files belonging to a diocese ",
     *     description="API: Use this endpoint to get all files by a diocese",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="user_id",
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
        $pld = files::where('user_id', $uid)->get();
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
        $dbd = partner_basic_data::where("user_id", $request->user_id)->first();
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
            "bnk"=> $request->bnk,
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
     *     path="/api/getSchoolsByPartner/{uid}",
     *     tags={"Api"},
     *     summary="Get Partner's Schools",
     *     description="Use this endpoint to get a Partner's Schools.",
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
    public function getSchoolsByPartner($uid){
        $start = 0;
        $count = 20;
        if(request()->has('start') && request()->has('count')) {
            $start = request()->input('start');
            $count = request()->input('count');
        }
        $members = school_basic_data::where('pcode',$uid)->skip($start)->take($count)->get();
        $pld = [];
        foreach ($members as $member) {
            $user_id = $member->user_id;
            $genData = school_general_data::where('user_id', $user_id)->first();
            $pld[] = [
                'b'=> $member,
                'g'=> $genData,
            ];
        }
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> $pld,
        ]);
    }

     /**
     * @OA\Get(
     *     path="/api/searchSchools",
     *     tags={"Api"},
     *     summary="Full text search on school names",
     *     description=" Use this endpoint for Full text search on school names",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="search",
     *         in="query",
     *         required=true,
     *         description="Search term",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function searchSchools(){
        $search = null;
        if(request()->has('search')) {
            $search = request()->input('search');
        }
        if($search) {
            $members = school_basic_data::whereRaw("MATCH(sname) AGAINST(? IN BOOLEAN MODE)", [$search])
            ->orderByRaw("MATCH(sname) AGAINST(? IN BOOLEAN MODE) DESC", [$search])
            ->take(2)
            ->get();
            $pld = [];
            foreach ($members as $member) {
                $user_id = $member->user_id;
                $genData = school_general_data::where('user_id', $user_id)->first();
                $pld[] = [
                    'b'=> $member,
                    'g'=> $genData,
                ];
            }
            return response()->json([
                "status"=> true,
                "message"=> "Success",
                "pld"=> $pld
            ]); 
        }
        return response()->json([
            "status"=> false,
            "message"=> "The Search param is required"
        ]);
    }

    /**
     * @OA\Get(
     *     path="/api/searchPartners",
     *     tags={"Api"},
     *     summary="Full text search on partner names",
     *     description=" Use this endpoint for Full text search on partner names",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="search",
     *         in="query",
     *         required=true,
     *         description="Search term",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function searchPartners(){
        $search = null;
        if(request()->has('search')) {
            $search = request()->input('search');
        }
        if($search) {
            $members = partner_basic_data::whereRaw("MATCH(fname, lname, mname) AGAINST(? IN BOOLEAN MODE)", [$search])
            ->orderByRaw("MATCH(fname, lname, mname) AGAINST(? IN BOOLEAN MODE) DESC", [$search])
            ->take(2)
            ->get();
            $pld = [];
            foreach ($members as $member) {
                $user_id = $member->user_id;
                $genData = partner_general_data::where('user_id', $user_id)->first();
                $pld[] = [
                    'b'=> $member,
                    'g'=> $genData,
                ];
            }
            return response()->json([
                "status"=> true,
                "message"=> "Success",
                "pld"=> $pld
            ]); 
        }
        return response()->json([
            "status"=> false,
            "message"=> "The Search param is required"
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
        $totalComsAmt = partner_coms::where('partner_id',$uid)->sum('amt');
        $totalComs = partner_coms::where('partner_id',$uid)->count();
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> [
                'totalSchools'=>$totalSchools,
                'totalComsAmt'=>$totalComsAmt,
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
        $members = announcements::take($count)->skip($start)->get();
        $pld = [];
        foreach ($members as $member) {
            $user_id = $member->user_id;
            $genData = school_general_data::where('user_id', $user_id)->first();
            $pld[] = [
                'b'=> $member,
                'g'=> $genData,
            ];
        }
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> $pld,
        ]);
    }


     /**
     * @OA\Get(
     *     path="/api/getMyMessages/{uid}",
     *     tags={"Api"},
     *     summary="Get Message Threads by UID",
     *     description="Use this endpoint to get messages Threads for this `uid`",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="uid",
     *         in="path",
     *         required=true,
     *         description="User ID",
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
    public function getMyMessages($uid){
        $start = 0;
        $count = 20;
        if(request()->has('start') && request()->has('count')) {
            $start = request()->input('start');
            $count = request()->input('count');
        }
        $pld = msgthread::where('from_uid', $uid)->orWhere('to_uid', $uid)->skip($start)->take($count)->get();
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> $pld,
        ]);
    }

     /**
     * @OA\Get(
     *     path="/api/getMessageThread/{tid}",
     *     tags={"Api"},
     *     summary="Get Messages by thread id",
     *     description="Use this endpoint to get messages for this `tid`",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="tid",
     *         in="path",
     *         required=true,
     *         description="Thread ID",
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
    public function getMessageThread($tid){
        $start = 0;
        $count = 20;
        if(request()->has('start') && request()->has('count')) {
            $start = request()->input('start');
            $count = request()->input('count');
        }
        $pld = msg::where('tid', $tid)->skip($start)->take($count)->get();
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> $pld,
        ]);
    }

    /**
     * @OA\Post(
     *     path="/api/createMsgThread",
     *     tags={"Api"},
     *     summary="Create a new message thread",
     *     description="Use this endpoint to create a new message thread.",
     *     security={{"bearerAuth": {}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="from", type="string", description="Name of the person sending"),
     *             @OA\Property(property="from_uid", type="string", description="User ID of the person sending"),
     *             @OA\Property(property="to", type="string", description="Name of the person receiving"),
     *             @OA\Property(property="to_uid", type="string", description="User ID of the person receiving"),
     *             @OA\Property(property="last_msg", type="string", description="Last Message (First in this case) - Shown in preview"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="Success"),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function createMsgThread(Request $request){
        $request->validate([
            "from"=> "required",
            "from_uid"=> "required",
            "to"=> "required",
            "to_uid"=> "required",
            "last_msg"=> "required",
        ]);
        $mt = msgthread::create([
            "from"=> $request->from,
            "from_uid"=> $request->from_uid,
            "to"=> $request->to,
            "to_uid"=> $request->to_uid,
            "last_msg"=> $request->last_msg,
        ]);
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=>[
                'id'=>strval($mt->id)
            ]
        ]);
    }

    /**
     * @OA\Post(
     *     path="/api/sendMsg",
     *     tags={"Api"},
     *     summary="Send a message",
     *     description="Use this endpoint to send a chat. You may also notify by mail",
     *     security={{"bearerAuth": {}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="subject", type="string", description="Subject of the announcement"),
     *             @OA\Property(property="body", type="string", description="Message content"),
     *             @OA\Property(property="who", type="string", description="User ID of the person sending"),
     *             @OA\Property(property="tid", type="string", description="Thread ID of the message"),
     *             @OA\Property(property="mail", type="string", description="If not empty, user will be mailed"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="Success"),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function sendMsg(Request $request){
        $request->validate([
            "subject"=>"required",
            "body"=> "required",
            "who"=> "required",
            "tid"=> "required",
            "mail"=> "required",
        ]);
        $trd = msgthread::where('id',intval($request->tid))->first();
        if($trd){
            msg::create([
                "tid"=> $request->tid,
                "subject"=> $request->subject,
                "body"=> $request->body,
                "who"=> $request->who,
            ]);
            if($request->mail!=''){
                $isPerson1 = $request->who == $trd->from_uid;
                $from = null;
                $to = null;
                if($isPerson1){
                    $from = $trd->from;
                    $to = $trd->to;
                }else{
                    $from = $trd->to;
                    $to = $trd->from;
                }
                $data = [
                    'name' => $from.' -> '.$to,
                    'subject' => $request->subject,
                    'body' => $request->body,
                    'link'=>'https://portal.schoolsilo.cloud'
                ];
            
                Mail::to($request->mail)->send(new SSSMails($data));
                return response()->json([
                    "status"=> true,
                    "message"=> "Success (User was also mailed"
                ]);
            }
            // Respond
            return response()->json([
                "status"=> true,
                "message"=> "Success"
            ]);
        }
        return response()->json([
            "status"=> false,
            "message"=> "Thread not found"
        ]);
    }


    


    //--------------- ADMIN CODES


     /**
     * @OA\Get(
     *     path="/api/getAdmin/{uid}",
     *     tags={"Api"},
     *     summary="Get Messages by thread id",
     *     description="Use this endpoint to get an admin info",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="uid",
     *         in="path",
     *         required=true,
     *         description="User ID",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function getAdmin($uid){
        $pld = admin_user::where('user_id', $uid)->first();
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> $pld,
        ]);
    }

    //POST
    public function setAdmin(Request $request){
        if ($this->hasRole('0')) {
            $request->validate([
                "user_id"=>"required",
                "lname"=>"required",
                "oname"=> "required",
                "eml"=> "required",
                "role"=>"required",
                "pd1"=> "required",
                "pd2"=> "required",
                "pp1"=>"required",
                "pp2"=> "required",
                "pm1"=> "required",
                "pm2"=>"required",
            ]);
            admin_user::updateOrCreate(
                ["user_id"=> $request->user_id,],
                [
                "lname"=> $request->lname,
                "oname"=> $request->oname,
                "eml"=> $request->eml,
                "role"=> $request->role,
                "pd1"=> $request->pd1,
                "pd2"=> $request->pd2,
                "pp1"=> $request->pp1,
                "pp2"=> $request->pp2,
                "pm1"=> $request->pm1,
                "pm2"=> $request->pm2,
            ]);
            // Respond
            return response()->json([
                "status"=> true,
                "message"=> "Admin Added"
            ]);
        }
        return response()->json([
            "status"=> false,
            "message"=> "Access denied"
        ],401);
    }


    /**
     * @OA\Get(
     *     path="/api/getAdminHighlights",
     *     tags={"Api"},
     *     summary="Get Highlights (Admin)",
     *     description=" Use this endpoint to get admin highlights.",
     *     security={{"bearerAuth": {}}},
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function getAdminHighlights(){
        $totalSchools = school_basic_data::count();
        $totalPartners = partner_basic_data::count();
        $totalPayments = school_basic_data::where('pay','1')->count();
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> [
                'totalSchools'=>$totalSchools,
                'totalPartners'=>$totalPartners,
                'totalPayments'=>$totalPayments
            ],
        ]);   
    }

    /**
     * @OA\Get(
     *     path="/api/getVerificationStats",
     *     tags={"Admin"},
     *     summary="ADMIN: Get Verification Stats (Admin)",
     *     description=" Use this endpoint to get verif stats.",
     *     security={{"bearerAuth": {}}},
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function getVerificationStats(){
        $schoolsVerif = school_basic_data::where('verif','1')->count();
        $schoolsNotVerif = school_basic_data::where('verif','0')->count();
        $schoolsDeleted = school_basic_data::where('verif','2')->count();
        $partnersVerif = partner_basic_data::where('verif','1')->count();
        $partnersNotVerif = partner_basic_data::where('verif','0')->count();
        $partnersDeleted = partner_basic_data::where('verif','2')->count();
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> [
                'schoolsVerif'=>$schoolsVerif,
                'schoolsNotVerif'=>$schoolsNotVerif,
                'schoolsDeleted'=>$schoolsDeleted,
                'partnersVerif'=>$partnersVerif,
                'partnersNotVerif'=>$partnersNotVerif,
                'partnersDeleted'=>$partnersDeleted,
            ],
        ]);   
    }


    /**
     * @OA\Get(
     *     path="/api/getPaymentStats",
     *     tags={"Admin"},
     *     summary="ADMIN: Get payments Stats (Admin)",
     *     description=" Use this endpoint to get pays stats.",
     *     security={{"bearerAuth": {}}},
     *     @OA\Response(response="200", description="Success", @OA\JsonContent()),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function getPaymentStats(){
        $schoolsPaid = school_basic_data::where('pay','1')->count();
        $schoolsNotPaid = school_basic_data::where('pay','0')->count();
        return response()->json([
            "status"=> true,
            "message"=> "Success",
            "pld"=> [
                'schoolsPaid'=>$schoolsPaid,
                'schoolsNotPaid'=>$schoolsNotPaid,
            ],
        ]);   
    }
    

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

    /**
     * @OA\Post(
     *     path="/api/sendMail",
     *     tags={"Admin"},
     *     summary="Send an email",
     *     description="ADMIN: Use this endpoint to create an announcement.",
     *     security={{"bearerAuth": {}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="name", type="string"),
     *             @OA\Property(property="email", type="string", format="email"),
     *             @OA\Property(property="subject", type="string"),
     *             @OA\Property(property="body", type="string"),
     *             @OA\Property(property="link", type="string"),
     *         )
     *     ),
     *     @OA\Response(response="200", description="Announcement created successfully"),
     *     @OA\Response(response="401", description="Unauthorized"),
     * )
     */
    public function sendMail(Request $request){
        if ( $this->permOk('pd2')) { //Can write to dir
            $request->validate([
                "name"=>"required",
                "email"=>"required",
                "subject"=>"required",
                "body"=> "required",
                "link"=> "required",
            ]);
            $data = [
                'name' => $request->name,
                'subject' => $request->subject,
                'body' => $request->body,
                'link' => $request->link,
            ];
        
            Mail::to($request->email)->send(new SSSMails($data));
            
            return response()->json([
                "status"=> true,
                "message"=> "Mailed Successfully",
            ]);   
        }
        return response()->json([
            "status"=> false,
            "message"=> "Access denied"
        ],401);
    }

    

    /**
     * @OA\Get(
     *     path="/api/getSchoolsByPay/{pid}",
     *     tags={"Admin"},
     *     summary="ADMIN: Get Schools by pay id",
     *     description="Use this endpoint to get schools",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="pid",
     *         in="path",
     *         required=true,
     *         description="pay ID",
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
    public function getSchoolsByPay($pid){
        if ( $this->hasRole('0')) {
            $start = 0;
            $count = 20;
            if(request()->has('start') && request()->has('count')) {
                $start = request()->input('start');
                $count = request()->input('count');
            }
            $members = school_basic_data::where('pay',$pid)->skip($start)->take($count)->get();
            $pld = [];
            foreach ($members as $member) {
                $user_id = $member->user_id;
                $genData = school_general_data::where('user_id', $user_id)->first();
                $pld[] = [
                    'b'=> $member,
                    'g'=> $genData,
                ];
            }
            // Respond
            return response()->json([
                "status"=> true,
                "message"=> "Success",
                "pld"=> $pld,
            ]);
        }
        return response()->json([
            "status"=> false,
            "message"=> "Access denied"
        ],401);
    }
   
    /**
     * @OA\Get(
     *     path="/api/getSchoolsByV/{vid}",
     *     tags={"Admin"},
     *     summary="ADMIN: Get Schools by verif id",
     *     description="Use this endpoint to get schools",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="vid",
     *         in="path",
     *         required=true,
     *         description="Verif ID",
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
    public function getSchoolsByV($vid){
        if ( $this->hasRole('0')) {
            $start = 0;
            $count = 20;
            if(request()->has('start') && request()->has('count')) {
                $start = request()->input('start');
                $count = request()->input('count');
            }
            $members = school_basic_data::where('verif',$vid)->skip($start)->take($count)->get();
            $pld = [];
            foreach ($members as $member) {
                $user_id = $member->user_id;
                $genData = school_general_data::where('user_id', $user_id)->first();
                $pld[] = [
                    'b'=> $member,
                    'g'=> $genData,
                ];
            }
            // Respond
            return response()->json([
                "status"=> true,
                "message"=> "Success",
                "pld"=> $pld,
            ]);
        }
        return response()->json([
            "status"=> false,
            "message"=> "Access denied"
        ],401);
    }

    /**
     * @OA\Get(
     *     path="/api/getPartnersByV/{vid}",
     *     tags={"Admin"},
     *     summary="ADMIN: Get Partners by verif id",
     *     description="Use this endpoint to get partners",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="vid",
     *         in="path",
     *         required=true,
     *         description="Verif ID",
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
    public function getPartnersByV($vid){
        if ( $this->hasRole('0')) {
            $start = 0;
            $count = 20;
            if(request()->has('start') && request()->has('count')) {
                $start = request()->input('start');
                $count = request()->input('count');
            }
            $members = partner_basic_data::where('verif',$vid)->skip($start)->take($count)->get();
            $pld = [];
            foreach ($members as $member) {
                $user_id = $member->user_id;
                $genData = partner_general_data::where('user_id', $user_id)->first();
                $pld[] = [
                    'b'=> $member,
                    'g'=> $genData,
                ];
            }
            // Respond
            return response()->json([
                "status"=> true,
                "message"=> "Success",
                "pld"=> $pld,
            ]);
        }
        return response()->json([
            "status"=> false,
            "message"=> "Access denied"
        ],401);
    }

    //POST
    public function setSchoolsiloInfo(Request $request){
        if ($this->hasRole('0')) {
            $request->validate([
                "user_id"=>"required",
                "cname"=>"required",
                "regno"=> "required",
                "addr"=> "required",
                "nationality"=>"required",
                "state"=> "required",
                "lga"=> "required",
                "aname"=>"required",
                "anum"=> "required",
                "bnk"=> "required",
                "pname"=>"required",
                "peml"=> "required",
                "pphn"=> "required",
                "paddr"=>"required",
                
            ]);
            schoolsilo_info::updateOrCreate(
                ["user_id"=> $request->user_id,],
                [
                "cname"=> $request->cname,
                "regno"=> $request->regno,
                "addr"=> $request->addr,
                "nationality"=> $request->nationality,
                "state"=> $request->state,
                "lga"=> $request->lga,
                "aname"=> $request->aname,
                "anum"=> $request->anum,
                "bnk"=> $request->bnk,
                "pname"=> $request->pname,
                "peml"=> $request->peml,
                "pphn"=> $request->pphn,
                "paddr"=> $request->paddr,
            ]);
            // Respond
            return response()->json([
                "status"=> true,
                "message"=> "School Silo Info updated"
            ]);
        }
        return response()->json([
            "status"=> false,
            "message"=> "Access denied"
        ],401);
    }

    //GET
    public function getSchoolsiloInfo($uid){
        if ($this->hasRole('0')) {
            $pld = schoolsilo_info::where('user_id', $uid)->first();
            if($pld){
                return response()->json([
                    "status"=> true,
                    "message"=> "Success",
                    "pld"=> $pld,
                ]);
            }
            return response()->json([
                "status"=> false,
                "message"=> "No Data Yet",
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
