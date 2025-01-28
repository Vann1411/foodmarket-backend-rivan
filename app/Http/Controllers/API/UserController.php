<?php

namespace App\Http\Controllers\API;

use App\Actions\Fortify\PasswordValidationRules;
use App\Helpers\ResponseFormatter;
use App\Http\controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;


class UserController extends Controller
{
    use PasswordValidationRules;

    public function login(Request $request)
    {        
        try {
            $request->validate([
                'email' => 'required|email',
                'password' => 'required|string',
            ]);

            $credentials = request(['email', 'password']);
            
            if(!Auth::attempt($credentials)){
                $dataError = [
                    'message' => 'Unauthorized'
                ];
                return ResponseFormatter::error($dataError, 'Authentication Failed', 500);
            }

            $user = User::where('email', $request->email)->first();

            if(!Hash::check($request->password, $user->password, [])){
                throw new \Exception("Invalid Credentials");
            }

            $tokenResult = $user->createToken('authToken')->plainTextToken;

            $arrResult = [
                'access_token' => $tokenResult,
                'token_type' =>'Bearer',
                'user' =>$user
            ];

            return ResponseFormatter::success($arrResult,'Authenticated');
        } catch (Exception $error) {
            $dataError = [
                'message' => 'something went wrong',
                'error' => $error
            ];

            return ResponseFormatter::error($dataError, 'Authentocation Failed', 500);
        }
    }

    public function register(Request $request)
    {
        try {
            $rules = [
                'name' => 'required|string|max:225',
                'email' =>['required', 'string', 'email', 'max:225', 'unique:users'],
                'password' => $this->passwordRules()
            ];

            Validator::make($request->all(), $rules)->validate();

            $dataUser = User::create([
                'name'          => $request->name,
                'email'         => $request->email,
                'address'       => $request->address ?? null,
                'houseNumber'   => $request->houseNumber ?? null,
                'phoneNumber'   => $request->phoneNumber ?? null,
                'city'          => $request->city ?? null,
                'password'      => Hash::make($request->password)
            ]);

            $tokenResult = $dataUser->createToken('authToken')->plainTextToken;

            $arrResult = [
                'access_token' => $tokenResult,
                'token_type'   => 'Bearer',
                'user'         => $dataUser 
            ];

            return ResponseFormatter::success($arrResult,'Register User Successfully');
        } catch (\Exception $error) {
            $dataError = [
                'message' => $error->getMessage(),
                'error' =>$error
            ];

            return ResponseFormatter::error($dataError, 'Authentication Failed', 500);
        }
    }
    public function logout(Request $request)
    {
        try {
            if(empty($request->user())){
                throw new \Exception("Parameter header bearer token tidak valid.");
            }

            $token = $request->user()->currentAccessToken()->delete();
            return ResponseFormatter::success($token, 'Token Revoked');
        } catch (\Exception $error) {
            $dataError = [
                'message' => $error->getMessage(),
                'error'   => $error
            ];

            return ResponseFormatter::error($dataError, 'Authentication Failed', 500);
        }
    }

    public function updateProfile(Request $request)
    {
        $rules = [
            'name' => $request->name ?? null,
        ];
        $data = $request->all();

        $user = Auth::user();
        
        $dataUpdate = [
            'name' =>$request->name ?? $user->name,
            'password' =>!empty($request->password) ? Hash::make($request->password) : $user->password,
            'address' =>$request->address ?? $user->address,
            'houseNumber' =>$request->houseNumber ?? $user->houseNumber,
            'phoneNumber' =>$request->phoneNumber ?? $user->phoneNumber,
            'city' =>$request->city ?? $user->city,
        ];
        $user->update($dataUpdate);

        return ResponseFormatter::success($user, 'profile Updated');
    }
}
