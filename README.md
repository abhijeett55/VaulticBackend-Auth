# JWT Authentication — Spring Boot + Spring Security + Angular

Login/Sign-up authentication system using **JWT (JSON Web Tokens)** on the backend with **Spring Boot & Spring Security**, connected to an **Angular** frontend.

---

## 📋 Table of Contents

- [Architecture Overview](#architecture-overview)
- [Tech Stack](#tech-stack)
- [Backend Setup](#backend-setup)
- [Authentication Flow](#authentication-flow)
- [Backend Implementation](#backend-implementation)
- [Frontend Setup (Angular)](#frontend-setup-angular)
- [Frontend Implementation](#frontend-implementation)
- [API Endpoints](#api-endpoints)
- [Security Notes](#security-notes)
- [Testing](#testing)
- [Environment Variables](#environment-variables)

---

## Architecture Overview

```
┌─────────────────┐        1. POST /auth/login          ┌──────────────────────┐
│                  │ ───────────────────────────────────▶│                       │
│  Angular Client  │                                       │   Spring Boot API    │
│  (localhost:4200)│ ◀─────────────────────────────────── │   Spring Security     │
│                  │        2. { accessToken, ... }        │   + JWT Filter        │
└──────┬───────────┘                                       └──────────┬───────────┘
       │                                                              │
       │  3. Subsequent requests:                                    │
       │     Authorization: Bearer <token>                           │
       └──────────────────────────────────────────────────────────▶  │
                                                                       ▼
                                                              ┌─────────────────┐
                                                              │   Database       │
                                                              │  (Users table)   │
                                                              └─────────────────┘
```

**Flow summary:**
1. User submits credentials → backend validates → issues a signed JWT.
2. Angular stores the token (in memory / secure storage) and attaches it to every request via an **HTTP Interceptor**.
3. A custom `JwtAuthenticationFilter` on the backend validates the token on every protected request before it reaches the controller.
4. Spring Security's `SecurityContext` is populated per-request — fully stateless, no server-side sessions.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Spring Boot 3.x, Spring Security 6.x |
| Token | JJWT (`io.jsonwebtoken`) or Nimbus JOSE |
| Password hashing | BCryptPasswordEncoder |
| Database | MongoDB / PostgreSQL (adjust repository layer accordingly) |
| Frontend | Angular 17+ (standalone components) |
| HTTP | Angular `HttpClient` + functional interceptor (`withInterceptors`) |

---

## Backend Setup

### 1. Dependencies (`pom.xml`)

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.12.5</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.12.5</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.12.5</version>
    <scope>runtime</scope>
</dependency>
```

### 2. Project structure

```
src/main/java/com/app/auth/
├── config/
│   ├── SecurityConfig.java
│   └── JwtAuthenticationFilter.java
├── controller/
│   └── AuthController.java
├── dto/
│   ├── LoginRequest.java
│   ├── RegisterRequest.java
│   └── AuthResponse.java
├── model/
│   └── User.java
├── repository/
│   └── UserRepository.java
├── service/
│   ├── AuthService.java
│   ├── JwtService.java
│   └── CustomUserDetailsService.java
```

---

## Authentication Flow

1. **Sign up** — user submits name/email/password → password hashed with BCrypt → user saved.
2. **Login** — credentials validated via `AuthenticationManager` → on success, `JwtService` generates a signed token containing the username + expiry.
3. **Protected requests** — Angular interceptor attaches `Authorization: Bearer <token>` header.
4. **Filter validation** — `JwtAuthenticationFilter` runs once per request, extracts + validates the token, loads user details, and sets the `SecurityContext`.
5. **Token expiry** — client either re-authenticates or (if implemented) uses a refresh token flow.

---

## Backend Implementation

### `JwtService.java` — token generation & validation

```java
@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long expiration; // e.g. 86400000 (24h) in ms

    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey())
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractClaims(token).getExpiration().before(new Date());
    }

    private Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
```

### `JwtAuthenticationFilter.java` — runs per request

```java
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);
        final String username = jwtService.extractUsername(jwt);

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
```

### `SecurityConfig.java`

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(Customizer.withDefaults())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/**").permitAll()
                .anyRequest().authenticated())
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authenticationProvider(authenticationProvider)
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(
            "https://your-frontend.vercel.app",
            "http://localhost:4200"
        ));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
```

### `AuthController.java`

```java
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }
}
```

---

## Frontend Setup (Angular)

### 1. Auth service — `auth.service.ts`

```typescript
import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, tap } from 'rxjs';

interface AuthResponse {
  accessToken: string;
  email: string;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private apiUrl = 'http://localhost:8080/auth';
  isAuthenticated = signal<boolean>(!!localStorage.getItem('token'));

  constructor(private http: HttpClient) {}

  login(email: string, password: string): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.apiUrl}/login`, { email, password })
      .pipe(tap(res => this.storeToken(res.accessToken)));
  }

  register(name: string, email: string, password: string): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.apiUrl}/register`, { name, email, password });
  }

  logout(): void {
    localStorage.removeItem('token');
    this.isAuthenticated.set(false);
  }

  getToken(): string | null {
    return localStorage.getItem('token');
  }

  private storeToken(token: string): void {
    localStorage.setItem('token', token);
    this.isAuthenticated.set(true);
  }
}
```

> ⚠️ `localStorage` is convenient but vulnerable to XSS. For production-grade apps, consider an **HttpOnly cookie** issued by the backend instead — it can't be read by JavaScript at all.

### 2. HTTP Interceptor — `auth.interceptor.ts` (Angular 17 functional style)

```typescript
import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from './auth.service';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const token = authService.getToken();

  if (token) {
    req = req.clone({
      setHeaders: { Authorization: `Bearer ${token}` }
    });
  }
  return next(req);
};
```

Register it in `app.config.ts`:

```typescript
import { ApplicationConfig } from '@angular/core';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { authInterceptor } from './auth.interceptor';

export const appConfig: ApplicationConfig = {
  providers: [
    provideHttpClient(withInterceptors([authInterceptor])),
  ]
};
```

### 3. Route guard — `auth.guard.ts`

```typescript
import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from './auth.service';

export const authGuard: CanActivateFn = () => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authService.isAuthenticated()) return true;

  router.navigate(['/login']);
  return false;
};
```

---

## API Endpoints

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `POST` | `/auth/register` | Create a new user | No |
| `POST` | `/auth/login` | Authenticate & receive JWT | No |
| `GET` | `/api/user/me` | Get current user profile | Yes (Bearer token) |
| `POST` | `/auth/logout` | Invalidate token (if blacklist implemented) | Yes |

**Sample login request:**
```json
POST /auth/login
{
  "email": "user@example.com",
  "password": "yourPassword123"
}
```

**Sample response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
  "email": "user@example.com"
}
```

---

## Security Notes

- **Passwords** are hashed with `BCryptPasswordEncoder` — never store plaintext.
- **JWT secret** must be a strong, random Base64-encoded key (256-bit minimum for HS256), stored in environment variables — never hardcoded or committed.
- **Token expiry** should be short-lived (15 min – 24 hr depending on sensitivity); pair with a refresh-token flow for longer sessions if needed.
- **Stateless sessions** — `SessionCreationPolicy.STATELESS` means no server-side session store; the JWT is the sole proof of identity per request.
- **CORS** — only allow origins you control (production domain + `localhost` for dev). Never use `allowedOrigins("*")` together with `allowCredentials(true)` — Spring will reject that combination outright.
- **HTTPS only** in production — JWTs sent over plain HTTP can be intercepted.
- Known gap to address later: no token blacklist/revocation on logout (JWTs remain valid until expiry even after "logout" unless you add a blacklist, e.g. via Redis).

---

## Testing

```bash
# Register
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"test@example.com","password":"password123"}'

# Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

# Access protected route
curl -X GET http://localhost:8080/api/user/me \
  -H "Authorization: Bearer <your-token-here>"
```

---

## Environment Variables

**Backend (`application.properties` / `application.yml`)**
```properties
jwt.secret=${JWT_SECRET}
jwt.expiration=86400000
spring.datasource.url=${DB_URL}
```

**Frontend (`environment.ts`)**
```typescript
export const environment = {
  production: false,
  apiUrl: 'http://localhost:8080'
};
```

---

## License

MIT
