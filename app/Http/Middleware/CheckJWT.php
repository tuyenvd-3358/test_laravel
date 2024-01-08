<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Tymon\JWTAuth\Facades\JWTAuth;

class CheckJWT
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            
            // Gửi request tiếp theo nếu token hợp lệ
            return $next($request);
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            // Xử lý khi token hết hạn
            return response()->json(['error' => 'Token expired'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            // Xử lý khi token không hợp lệ
            return response()->json(['error' => 'Token invalid'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            // Xử lý khi không có token trong request
            return response()->json(['error' => 'Token not provided'], 401);
        }

        // Nếu xảy ra lỗi khác, trả về lỗi không được ủy quyền truy cập
        return response()->json(['error' => 'Unauthorized'], 401);
        }
    }
