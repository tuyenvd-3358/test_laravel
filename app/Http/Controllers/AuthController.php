<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;

use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Validator;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    //  /**
    //  * Create a new AuthController instance.
    //  *
    //  * @return void
    //  */
    // public function __construct() {
    //     $this->middleware('auth:api', ['except' => ['login', 'register']]);
    // }

    // public function login(Request $request){
    // 	$validator = Validator::make($request->all(), [
    //         'email' => 'required|email',
    //         'password' => 'required|string|min:6',
    //     ]);

    //     if ($validator->fails()) {
    //         return response()->json($validator->errors(), 422);
    //     }

    //     if (! $token = auth()->attempt($validator->validated())) {
    //         return response()->json(['error' => 'Unauthorized'], 401);
    //     }

    //     return $this->createNewToken($token);
    // }

    // /**
    //  * Register a User.
    //  *
    //  * @return \Illuminate\Http\JsonResponse
    //  */
    // public function register(Request $request) {
    //     $validator = Validator::make($request->all(), [
    //         'name' => 'required|string|between:2,100',
    //         'email' => 'required|string|email|max:100|unique:users',
    //         'password' => 'required|string|min:6',
    //     ]);

    //     if($validator->fails()){
    //         return response()->json($validator->errors()->toJson(), 400);
    //     }

    //     $user = User::create(array_merge(
    //                 $validator->validated(),
    //                 ['password' => bcrypt($request->password)]
    //             ));

    //     return response()->json([
    //         'message' => 'User successfully registered',
    //         'user' => $user
    //     ], 201);
    // }


    // /**
    //  * Log the user out (Invalidate the token).
    //  *
    //  * @return \Illuminate\Http\JsonResponse
    //  */
    // public function logout() {
    //     auth()->logout();

    //     return response()->json(['message' => 'User successfully signed out']);
    // }

    // /**
    //  * Refresh a token.
    //  *
    //  * @return \Illuminate\Http\JsonResponse
    //  */
    // public function refresh() {
    //     return $this->createNewToken(auth()->refresh());
    // }

    // /**
    //  * Get the authenticated User.
    //  *
    //  * @return \Illuminate\Http\JsonResponse
    //  */
    // public function userProfile() {
    //     return response()->json(auth()->user());
    // }

    // /**
    //  * Get the token array structure.
    //  *
    //  * @param  string $token
    //  *
    //  * @return \Illuminate\Http\JsonResponse
    //  */
    // protected function createNewToken($token){
    //     return response()->json([
    //         'access_token' => $token,
    //         'token_type' => 'bearer',
    //         'expires_in' => auth()->factory()->getTTL() * 60,
    //         'user' => auth()->user()
    //     ]);
    // }

    // public function changePassWord(Request $request) {
    //     $validator = Validator::make($request->all(), [
    //         'old_password' => 'required|string|min:6',
    //         'new_password' => 'required|string|confirmed|min:6',
    //     ]);

    //     if($validator->fails()){
    //         return response()->json($validator->errors()->toJson(), 400);
    //     }
    //     $userId = auth()->user()->id;

    //     $user = User::where('id', $userId)->update(
    //                 ['password' => bcrypt($request->new_password)]
    //             );

    //     return response()->json([
    //         'message' => 'User successfully changed password',
    //         'user' => $user,
    //     ], 201);
    // }

    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    public function login(Request $request)
{
    $credentials = $request->only('email', 'password');

    if (!$token = JWTAuth::attempt($credentials)) {
        return response()->json(['error' => 'Unauthorized'], 401);
    }

    $user = JWTAuth::user();

    return response()->json([
        'token' => $token,
        'user' => $user
    ]);
}

public function register(Request $request)
{
    // Logic xử lý đăng ký người dùng mới

    $user = User::create([
        'name' => $request->input('name'),
        'email' => $request->input('email'),
        'password' => bcrypt($request->input('password')),
    ]);

    $token = JWTAuth::fromUser($user);

    return response()->json(compact('user', 'token'), 201);
}

public function logout(Request $request)
{
    JWTAuth::invalidate(JWTAuth::getToken());

    return response()->json(['message' => 'Logged out successfully']);
}

public function userProfile(Request $request)
{
    $user = JWTAuth::parseToken()->authenticate();

    return response()->json(compact('user'));
}

public function createNewToken(Request $request)
{
    $token = JWTAuth::refresh(JWTAuth::getToken());

    return response()->json(compact('token'));
}

    public function refresh() {
        return $this->createNewToken(auth()->refresh());
    }



}
