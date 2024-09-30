<?php

namespace App\Http\Controllers;

use App\Http\Requests\CreateUser;
use App\Models\Failed_login;
use App\Models\User;
use App\Models\Notification_user;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

/**
* @OA\Info(
*             title="Api Login", 
*             version="1.0",
*             description="Apis para login, creacion y logout de usuarios"
* )
*
* @OA\Server(url="http://localhost:8000")
*/

class LoginController extends Controller
{   
/**
 * Metodo Login
 * @OA\POST (
 *     path="/login_user",
 *     tags={"Login"},
 *     summary="Autenticación de usuario",
 *     description="Este método permite realizar la autenticación de un usuario en la aplicación",
 *     @OA\Parameter(
 *         name="username",
 *         in="query",
 *         required=true,
 *         @OA\Schema(type="string"),
 *         description="Nombre de usuario para el login",
 *         example="usuario123"
 *     ),
 *     @OA\Parameter(
 *         name="password",
 *         in="query",
 *         required=true,
 *         @OA\Schema(type="string"),
 *         description="Contraseña del usuario para el login",
 *         example="password123"
 *     ),
 *     @OA\Response(
 *         response=200,
 *         description="Login de usuario exitoso",
 *         @OA\JsonContent(
 *             @OA\Property(
 *                 type="array",
 *                 property="rows",
 *                 @OA\Items(
 *                     type="object",
 *                     @OA\Property(
 *                         property="username",
 *                         type="string",
 *                         example="usuario123"
 *                     ),
 *                     @OA\Property(
 *                         property="password",
 *                         type="string",
 *                         example="password123"
 *                     )
 *                 )
 *             )
 *         )
 *     ),
 *     @OA\Response(
 *         response=400,
 *         description="Datos faltantes",
 *         @OA\JsonContent(
 *             @OA\Property(
 *                 property="message",
 *                 type="string",
 *                 example="No existen coincidencias por este usuario [App\\Models\\User]"
 *             )
 *         )
 *     )
 * )
 */
    public function login_sesion(Request $request){
        $credentials = $request->only('username', 'password');
        $validator = Validator::make($credentials, [
            'username' => 'required',
            'password' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'errors' => $validator->errors()
            ], 400);
        }

        if (Auth::attempt($credentials)) {
            $user = $request->user();
            if(!is_null($user->tokens())){
                $user->tokens()->delete();
            }
            
            $tokenResult = $user->createToken('Personal Access Token: '.$user->username);
            $token = $tokenResult->plainTextToken;

            $update_session = User::find($user->id);
            $update_session->session = 1;
            $update_session->update();

            return response()->json([
                'response' => [
                    "user" => User::find($user->id),
                    "token" => $token
                ],
                'success' => 'Login satisfactorio'
            ], 200);

        }else{
            $login_user = User::where("username", $request->username)->get();
            if (!empty($login_user)) {
                $faileds_login = Failed_login::getFailedLogins($login_user[0]["id"]);
                if (count($faileds_login) == 3) {         
                    Notification_user::createTrack($login_user[0]["id"], 1);

                    $update_session = User::find($login_user[0]["id"]);
                    $update_session->status = 0;
                    $update_session->update();

                    return response()->json([
                        'errors' => 'Maximo de intentos alcanzados, se bloqueo el usuario'
                    ], 400);
                }else{
                    $create_fail_login = new Failed_login();
                    $create_fail_login->user_id = $login_user[0]["id"];
                    $create_fail_login->save();
                }
            }

            return response()->json([
                'errors' => 'Los datos ingresados son incorrectos'
            ], 400);
        }
    }

    // Metodo cerrar sesion
    public function logout_user(Request $request){        
        $user = User::find($request->id);
        $user->tokens()->delete();

        $update_session = User::find($user->id);
        $update_session->session = 0;
        $update_session->update();
        
        return response()->json([
            'success' => 'Sesion cerrada',
        ], 200);
    }

/**
 * Método create_user para crear usuario
 * @OA\Post(
 *     path="/crear_usuario",
 *     tags={"Usuarios"},
 *     summary="Creación de un nuevo usuario",
 *     description="Permite crear un nuevo usuario en la aplicación.",
 *     @OA\RequestBody(
 *         required=true,
 *         @OA\JsonContent(
 *             required={"email", "username", "name", "lastname", "password", "type_user", "phone_number"},
 *             @OA\Property(
 *                 property="email",
 *                 type="string",
 *                 format="email",
 *                 description="Email del usuario",
 *                 example="usuario@gmail.com"
 *             ),
 *             @OA\Property(
 *                 property="username",
 *                 type="string",
 *                 description="Nombre de usuario",
 *                 example="usuario123"
 *             ),
 *             @OA\Property(
 *                 property="name",
 *                 type="string",
 *                 description="Nombre del usuario",
 *                 example="Usuario"
 *             ),
 *             @OA\Property(
 *                 property="lastname",
 *                 type="string",
 *                 description="Apellido del usuario",
 *                 example="Ejemplo"
 *             ),
 *             @OA\Property(
 *                 property="password",
 *                 type="string",
 *                 format="password",
 *                 description="Contraseña del usuario",
 *                 example="password123"
 *             ),
 *             @OA\Property(
 *                 property="type_user",
 *                 type="integer",
 *                 description="Tipo de usuario (1 para administrador, 2 para usuario regular)",
 *                 example=1
 *             ),
 *             @OA\Property(
 *                 property="phone_number",
 *                 type="string",
 *                 description="Número de teléfono del usuario",
 *                 example="+541123455687"
 *             )
 *         )
 *     ),
 *     @OA\Response(
 *         response=200,
 *         description="Usuario creado exitosamente",
 *         @OA\JsonContent(
 *             @OA\Property(
 *                 property="message",
 *                 type="string",
 *                 example="Usuario creado exitosamente"
 *             ),
 *             @OA\Property(
 *                 property="user",
 *                 type="object",
 *                 @OA\Property(
 *                     property="id",
 *                     type="integer",
 *                     example=10
 *                 ),
 *                 @OA\Property(
 *                     property="email",
 *                     type="string",
 *                     example="usuario@gmail.com"
 *                 ),
 *                 @OA\Property(
 *                     property="username",
 *                     type="string",
 *                     example="usuario123"
 *                 ),
 *                 @OA\Property(
 *                     property="name",
 *                     type="string",
 *                     example="Usuario"
 *                 ),
 *                 @OA\Property(
 *                     property="lastname",
 *                     type="string",
 *                     example="Ejemplo"
 *                 ),
 *                 @OA\Property(
 *                     property="type_user",
 *                     type="integer",
 *                     example=1
 *                 ),
 *                 @OA\Property(
 *                     property="phone_number",
 *                     type="string",
 *                     example="+541123455687"
 *                 )
 *             )
 *         )
 *     ),
 *     @OA\Response(
 *         response=400,
 *         description="Datos faltantes o incorrectos",
 *         @OA\JsonContent(
 *             @OA\Property(
 *                 property="message",
 *                 type="string",
 *                 example="Error en la solicitud. Faltan datos obligatorios."
 *             )
 *         )
 *     ),
 *     @OA\Response(
 *         response=500,
 *         description="Error interno del servidor",
 *         @OA\JsonContent(
 *             @OA\Property(
 *                 property="message",
 *                 type="string",
 *                 example="Error al crear el usuario. Por favor intente nuevamente más tarde."
 *             )
 *         )
 *     )
 * )
 */
    public function create_user(Request $request) {
        
        $credentials = $request->only('email', 'username', 'name', 'lastname', 'password', 'type_user', 'phone_number');
        $validator = Validator::make($credentials, [
            'email' => [
                'required',
                'email',
                'unique:users,email',
                'regex:/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/',
                'max:64'
            ],
            'username' => 'required|string|alpha_dash|unique:users,username|min:3|max:15',
            'name' => 'required|string|min:2|max:50',
            'lastname' => 'required|string|min:2|max:50',
            'password' => 'required|string|min:8|max:30',
            'type_user' => 'required|integer|in:1,2',
            'phone_number' => [
                'required',
                'string',
                'regex:/^\+?[1-9]\d{7,19}$/',
            ],

        ]);

        if ($validator->fails()) {
            return response()->json([
                'errors' => $validator->errors()
            ], 400);
        }
        
        $user = User::create([
            'username' => $request->input('username'),
            'name' => $request->input('name'),
            'lastname' => $request->input('lastname'),
            'email' => $request->input('email'),
            'password' => Hash::make($request->input('password')),
            'phone_number' => $request->input('phone_number'),
            'type_user' => $request->input('type_user'),
            'status' => 1,
            'session' => 1,
        ]);
        
        $dataUser = User::find($user->id);
        return response()->json(['message' => 'Usuario creado', 'user' => $dataUser], 200);
    }

}