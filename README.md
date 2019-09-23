# JWT - Laravel 6 (2019)

**프로젝트 생성 및 jwt 라이브러리 설치**

    composer create-project --prefer-dist laravel/laravel laravel6-jwt.test "6.*"
    cd laravel6-jwt.test
    chmod -R 777 bootstrap/cache/
    chmod -R 777 storage/

**jwt 라이브러리 설치**

    composer require tymon/jwt-auth:1.0.x-dev
    php artisan jwt:secret

**jwt.php 설정 파일 생성**

    php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"

    php artisan migrate
    php artisan make:controller AuthController

**service provider 등록**

    vi config/app.php

    <?php
    'providers' => [
      ...
      Tymon\JWTAuth\Providers\LaravelServiceProvider::class,
    ],
    'alias' => [
      ...
      'JWTAuth' => Tymon\JWTAuth\Facades\JWTAuth::class,
    ],

**라우팅 정보 입력**

    vi routes/api.php

    Route::group([
    
        'middleware' => 'api',
        'prefix' => 'auth'
    
    ], function ($router) {
    
        Route::post('login', 'AuthController@login');
        Route::post('logout', 'AuthController@logout');
        Route::post('refresh', 'AuthController@refresh');
        Route::post('me', 'AuthController@me');
    
    });

app/User.php 모델 파일 편집

    vi app/User.php

    <?php
    
    namespace App;
    
    use Tymon\JWTAuth\Contracts\JWTSubject;
    use Illuminate\Notifications\Notifiable;
    use Illuminate\Foundation\Auth\User as Authenticatable;
    
    class User extends Authenticatable implements JWTSubject
    {
        use Notifiable;
    
        /**
         * The attributes that are mass assignable.
         *
         * @var array
         */
        protected $fillable = [
            'name', 'email', 'password',
        ];
    
        /**
         * The attributes that should be hidden for arrays.
         *
         * @var array
         */
        protected $hidden = [
            'password', 'remember_token',
        ];
    
        // Rest omitted for brevity
    
        /**
         * Get the identifier that will be stored in the subject claim of the JWT.
         *
         * @return mixed
         */
        public function getJWTIdentifier()
        {
            return $this->getKey();
        }
    
        /**
         * Return a key value array, containing any custom claims to be added to the JWT.
         *
         * @return array
         */
        public function getJWTCustomClaims()
        {
            return [];
        }
    }

**AuthController.php 편집**

    vi app/Http/Controllers/AuthController.php

    <?php
    
    namespace App\Http\Controllers;
    
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Auth;
    use App\Http\Controllers\Controller;
    
    class AuthController extends Controller
    {
        /**
         * Create a new AuthController instance.
         *
         * @return void
         */
        public function __construct()
        {
            $this->middleware('auth:api', ['except' => ['login']]);
        }
    
        /**
         * Get a JWT token via given credentials.
         *
         * @param  \Illuminate\Http\Request  $request
         *
         * @return \Illuminate\Http\JsonResponse
         */
        public function login(Request $request)
        {
            $credentials = $request->only('email', 'password');
    
            if ($token = $this->guard()->attempt($credentials)) {
                return $this->respondWithToken($token);
            }
    
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    
        /**
         * Get the authenticated User
         *
         * @return \Illuminate\Http\JsonResponse
         */
        public function me()
        {
            return response()->json($this->guard()->user());
        }
    
        /**
         * Log the user out (Invalidate the token)
         *
         * @return \Illuminate\Http\JsonResponse
         */
        public function logout()
        {
            $this->guard()->logout();
    
            return response()->json(['message' => 'Successfully logged out']);
        }
    
        /**
         * Refresh a token.
         *
         * @return \Illuminate\Http\JsonResponse
         */
        public function refresh()
        {
            return $this->respondWithToken($this->guard()->refresh());
        }
    
        /**
         * Get the token array structure.
         *
         * @param  string $token
         *
         * @return \Illuminate\Http\JsonResponse
         */
        protected function respondWithToken($token)
        {
            return response()->json([
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => $this->guard()->factory()->getTTL() * 60
            ]);
        }
    
        /**
         * Get the guard to be used during authentication.
         *
         * @return \Illuminate\Contracts\Auth\Guard
         */
        public function guard()
        {
            return Auth::guard();
        }
    }

**config/auth.php 파일 편집**

    vi config/auth.php

    'defaults' => [
            'guard' => 'api',
            'passwords' => 'users',
        ],
        'guards' => [
    		...
            'api' => [
                'driver' => 'jwt',
                'provider' => 'users',
            ],
        'providers' => [
            'users' => [
                'driver' => 'eloquent',
                'model' => App\Models\User::class, // 사용자 테이블이 다른 경우에 수정이 필요함
            ],
    
        ],

**디비 접속 정보 변경**

    vi .env

    ...
    DB_CONNECTION=mysql
    DB_HOST=127.0.0.1
    DB_PORT=3306
    DB_DATABASE=db_name
    DB_USERNAME=db_username
    DB_PASSWORD=db_password
    ...

**회원 생성**

    php artisan tinker

    $user = new User;
    $user->email = 'admin@admin.com';
    $user->name = 'admin';
    $user->password = Hash::make('password');
    $user->save();

**로그인**

    http post [http://laravel6-jwt.test/api/auth/login](http://laravel-jwt.test/api/auth/login) email=admin@admin.com password=password

    HTTP/1.1 200 OK
    Cache-Control: no-cache, private
    Connection: keep-alive
    Content-Type: application/json
    Date: Mon, 23 Sep 2019 07:23:37 GMT
    Server: nginx/1.14.0 (Ubuntu)
    Transfer-Encoding: chunked
    X-RateLimit-Limit: 60
    X-RateLimit-Remaining: 59
    
    {
        "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9sYXJhdmVsNi1qd3QudGVzdFwvYXBpXC9hdXRoXC9sb2dpbiIsImlhdCI6MTU2OTIyMzQxNywiZXhwIjoxNTY5MjI3MDE3LCJuYmYiOjE1NjkyMjM0MTcsImp0aSI6IkI0Y3c5R0pjZEFpdnZ4cDciLCJzdWIiOjEsInBydiI6Ijg3ZTBhZjFlZjlmZDE1ODEyZmRlYzk3MTUzYTE0ZTBiMDQ3NTQ2YWEifQ.gzlB4ipYZy_ps5dn1AFEtPEAPVh7DnsA4Qb0Y0y_fDI",
        "expires_in": 3600,
        "token_type": "bearer"
    }

**회원정보**

    http post http://laravel6-jwt.test/api/auth/me 'Authorization:bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9sYXJhdmVsNi1qd3QudGVzdFwvYXBpXC9hdXRoXC9sb2dpbiIsImlhdCI6MTU2OTIyMzQxNywiZXhwIjoxNTY5MjI3MDE3LCJuYmYiOjE1NjkyMjM0MTcsImp0aSI6IkI0Y3c5R0pjZEFpdnZ4cDciLCJzdWIiOjEsInBydiI6Ijg3ZTBhZjFlZjlmZDE1ODEyZmRlYzk3MTUzYTE0ZTBiMDQ3NTQ2YWEifQ.gzlB4ipYZy_ps5dn1AFEtPEAPVh7DnsA4Qb0Y0y_fDI'

    HTTP/1.1 200 OK
    Cache-Control: no-cache, private
    Connection: keep-alive
    Content-Type: application/json
    Date: Mon, 23 Sep 2019 07:26:00 GMT
    Server: nginx/1.14.0 (Ubuntu)
    Transfer-Encoding: chunked
    X-RateLimit-Limit: 60
    X-RateLimit-Remaining: 59
    
    {
        "created_at": "2019-09-23 07:20:06",
        "email": "admin@admin.com",
        "email_verified_at": null,
        "id": 1,
        "name": "admin",
        "updated_at": "2019-09-23 07:20:06"
    }

**로그아웃**

    http post [http://laravel6-jwt.test/api/auth/logout](http://laravel-jwt.test/api/auth/logout) 'Authorization:bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9sYXJhdmVsNi1qd3QudGVzdFwvYXBpXC9hdXRoXC9sb2dpbiIsImlhdCI6MTU2OTIyMzQxNywiZXhwIjoxNTY5MjI3MDE3LCJuYmYiOjE1NjkyMjM0MTcsImp0aSI6IkI0Y3c5R0pjZEFpdnZ4cDciLCJzdWIiOjEsInBydiI6Ijg3ZTBhZjFlZjlmZDE1ODEyZmRlYzk3MTUzYTE0ZTBiMDQ3NTQ2YWEifQ.gzlB4ipYZy_ps5dn1AFEtPEAPVh7DnsA4Qb0Y0y_fDI'

    HTTP/1.1 200 OK
    Cache-Control: no-cache, private
    Connection: keep-alive
    Content-Type: application/json
    Date: Mon, 23 Sep 2019 07:26:52 GMT
    Server: nginx/1.14.0 (Ubuntu)
    Transfer-Encoding: chunked
    X-RateLimit-Limit: 60
    X-RateLimit-Remaining: 57
    
    {
        "message": "Successfully logged out"
    }