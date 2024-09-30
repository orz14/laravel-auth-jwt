<?php

namespace App\Http\Controllers;

use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    protected function generateRefreshToken($unique)
    {
        $secretKey = config('secret.key');

        $uniqueData = sprintf('%s:%s:%s', $unique, time(), bin2hex(random_bytes(16)));
        $refreshToken = hash_hmac('sha256', $uniqueData, $secretKey);

        return $refreshToken;
    }

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'type' => 'validation_error',
                'errors' => $validator->errors(),
            ], 400);
        }

        try {
            $random = substr(base_convert(sha1(uniqid(mt_rand())), 16, 36), 0, 5);
            $refresh_token = $this->generateRefreshToken($random);

            $user = User::create([
                'name' => $request->input('name'),
                'email' => $request->input('email'),
                'password' => Hash::make($request->input('password')),
                'refresh_token' => $refresh_token,
            ]);

            $expiration = Carbon::now()->addHour()->timestamp;

            $payload = [
                'data' => [
                    'user_id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'refresh_token' => $user->refresh_token,
                ],
                'exp' => $expiration,
            ];

            $token = JWTAuth::customClaims($payload)->fromUser($user);

            return response()->json([
                'status' => true,
                'data' => $user,
                'token' => $token,
                'token_type' => 'Bearer',
                'expires_at' => Carbon::createFromTimestamp($expiration)->toDateTimeString(),
            ], 201);
        } catch (\Throwable $err) {
            return response()->json([
                'status' => false,
                'type' => 'internal_error',
                'message' => $err->getMessage(),
            ], 500);
        }
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'type' => 'validation_error',
                'errors' => $validator->errors(),
            ], 400);
        }

        try {
            if (! auth()->attempt($request->only('email', 'password'))) {
                return response()->json([
                    'status' => false,
                    'type' => 'invalid_credentials',
                ], 400);
            }

            $user = auth()->user();
            $refresh_token = $this->generateRefreshToken($user->id);
            $user['refresh_token'] = $refresh_token;

            User::find($user->id)->update([
                'refresh_token' => $refresh_token,
            ]);

            $expiration = Carbon::now()->addHour()->timestamp;
            // $expiration = Carbon::now()->addMinute(1)->timestamp;

            $payload = [
                'data' => [
                    'user_id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'refresh_token' => $refresh_token,
                ],
                'exp' => $expiration,
            ];

            $token = JWTAuth::customClaims($payload)->fromUser($user);

            return response()->json([
                'status' => true,
                'token' => $token,
                'token_type' => 'Bearer',
                'expires_at' => Carbon::createFromTimestamp($expiration)->toDateTimeString(),
            ], 200);
        } catch (JWTException $err) {
            return response()->json([
                'status' => false,
                'type' => 'internal_error',
                'message' => $err->getMessage(),
            ], 500);
        }
    }

    public function getAuthenticatedUser()
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();

            if (! $user) {
                return response()->json([
                    'status' => false,
                    'type' => 'user_not_found',
                ], 404);
            }

            return response()->json([
                'status' => true,
                'data' => $user,
            ], 200);
        } catch (TokenExpiredException $err) {
            return response()->json([
                'status' => false,
                'type' => 'token_expired',
                'message' => $err->getMessage(),
            ]);
        } catch (TokenInvalidException $err) {
            return response()->json([
                'status' => false,
                'type' => 'token_invalid',
                'message' => $err->getMessage(),
            ]);
        } catch (JWTException $err) {
            return response()->json([
                'status' => false,
                'type' => 'token_absent',
                'message' => $err->getMessage(),
            ]);
        }
    }

    public function checkToken()
    {
        try {
            $jwt = JWTAuth::parseToken();
            $token = $jwt->getToken()->get();
            $exp = $jwt->getPayload()->get('exp');

            if (! $token) {
                return response()->json([
                    'status' => false,
                    'type' => 'token_not_provided',
                ], 400);
            }

            return response()->json([
                'status' => true,
                'token' => $token,
                'token_type' => 'Bearer',
                'expires_at' => Carbon::createFromTimestamp($exp)->toDateTimeString(),
            ], 200);
        } catch (JWTException $err) {
            return response()->json([
                'status' => false,
                'type' => 'token_invalid',
                'message' => $err->getMessage(),
            ], 500);
        }
    }

    public function refreshToken()
    {
        try {
            $expiresAt = JWTAuth::parseToken()->getPayload()->get('exp');
            $expirationDate = Carbon::createFromTimestamp($expiresAt);
            $now = Carbon::now();

            if ($now->greaterThan($expirationDate) || $now->greaterThan($expirationDate->subMinutes(5))) {
                $user = auth()->user();
                $refresh_token = JWTAuth::parseToken()->getPayload()->get('data.refresh_token');

                if ($user->refresh_token == $refresh_token) {
                    $newToken = JWTAuth::parseToken()->refresh();

                    return response()->json([
                        'status' => true,
                        'type' => 'refresh_success',
                        'token' => $newToken,
                        'token_type' => 'Bearer',
                    ], 200);
                } else {
                    User::find($user->id)->update([
                        'refresh_token' => null,
                    ]);

                    auth()->logout();

                    return response()->json([
                        'status' => false,
                        'type' => 'refresh_failed',
                    ], 400);
                }
            } else {
                $token = JWTAuth::parseToken()->getToken()->get();

                return response()->json([
                    'status' => true,
                    'type' => 'refresh_none',
                    'token' => $token,
                    'token_type' => 'Bearer',
                ], 200);
            }
        } catch (JWTException $err) {
            return response()->json([
                'status' => false,
                'type' => 'internal_error',
                'error' => 'Token cannot be refreshed, it might be invalid or expired',
                'message' => $err->getMessage(),
            ], 401);
        }
    }

    public function logout()
    {
        try {
            User::find(auth()->user()->id)->update([
                'refresh_token' => null,
            ]);

            auth()->logout();

            return response()->json([
                'status' => true,
                'message' => 'Logged out',
            ], 200);
        } catch (\Throwable $err) {
            return response()->json([
                'status' => false,
                'message' => $err->getMessage(),
            ], 500);
        }
    }
}
