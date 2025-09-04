# Rate Limiting Example with axum-gate

This example demonstrates how to integrate axum-gate with tower's built-in rate limiting capabilities to protect your authentication endpoints and API routes from abuse.

## Features Demonstrated

- **Login Rate Limiting**: Prevents brute force attacks on login endpoints using tower's `RateLimitLayer`
- **Route-Specific Rate Limiting**: Different limits for different endpoint types
- **Global Rate Limiting**: Overall application protection
- **Integration with axum-gate**: Seamless authentication and authorization
- **Layered Middleware**: Proper composition of rate limiting with authentication

## Rate Limiting Strategy

### 1. Login Protection
- **Limit**: 5 requests per minute for login endpoints
- **Purpose**: Prevent brute force attacks
- **Implementation**: `RateLimitLayer::new(5, Duration::from_secs(60))`

### 2. Dashboard Protection
- **Limit**: 30 requests per minute for authenticated dashboard
- **Purpose**: Prevent API abuse from authenticated users
- **Implementation**: Applied before authentication middleware

### 3. Admin Protection
- **Limit**: 10 requests per minute for admin endpoints
- **Purpose**: Strict limits for sensitive administrative functions
- **Implementation**: Applied before authentication middleware

Note: This example demonstrates route-specific rate limiting. Global rate limiting can be added as an additional layer if needed.

## Running the Example

```bash
# From the project root
cargo run --example rate-limiting

# Or from the example directory
cd examples/rate-limiting
cargo run
```

The server will start on `http://127.0.0.1:3000`.

## Test Accounts

- **Username**: `admin`, **Password**: `admin` (admin permissions)
- **Username**: `user`, **Password**: `user` (user permissions)

## Testing Rate Limits

### Login Rate Limiting
1. Try logging in with wrong credentials repeatedly
2. After 5 failed attempts within a minute, tower will return HTTP 429 (Too Many Requests)
3. Wait a minute for the rate limit to reset

### Dashboard Rate Limiting
1. Log in successfully
2. Navigate to `/dashboard`
3. Rapidly refresh the page (F5 or Ctrl+R)
4. After 30 requests in a minute, you'll get a 429 error

### Admin Rate Limiting
1. Log in as admin
2. Navigate to `/admin`
3. Rapidly refresh the page
4. After 10 requests in a minute, you'll get a 429 error

### Testing Different Route Limits
1. Compare the different rate limits by testing login (5/min), dashboard (30/min), and admin (10/min) endpoints
2. Notice how each route has its own independent rate limiting

## Implementation Details

### Middleware Stack Architecture

The example uses tower's `ServiceBuilder` to compose middleware layers:

```rust
// Route-specific rate limiting for login
.route("/login", get(login_page_handler).post(login_handler))
.layer(
    ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|_: BoxError| async move {
            StatusCode::TOO_MANY_REQUESTS
        }))
        .layer(BufferLayer::new(1024))
        .layer(RateLimitLayer::new(5, Duration::from_secs(60)))
)

// Protected route with rate limiting + authentication
.route(
    "/dashboard",
    get(dashboard_handler).layer(
        ServiceBuilder::new()
            .layer(HandleErrorLayer::new(|_: BoxError| async move {
                StatusCode::TOO_MANY_REQUESTS
            }))
            .layer(BufferLayer::new(1024))
            .layer(RateLimitLayer::new(30, Duration::from_secs(60)))
            .layer(
                Gate::cookie("my-app", jwt_codec)
                    .with_policy(AccessPolicy::require_role(Role::User))
            ),
    ),
)

// Global middleware applied to all routes
.layer(TraceLayer::new_for_http())
```

### Middleware Order

The order of middleware layers is important:

1. **Error Handling** (outermost) - Converts rate limit errors to HTTP 429
2. **Buffer Layer** - Makes the service cloneable for axum
3. **Rate Limiting** - Controls request frequency
4. **Authentication** (axum-gate) - Validates JWT and sets user context (where applicable)
5. **Handler** (innermost) - Your business logic

### Required Middleware Components

#### HandleErrorLayer
- Converts rate limiting errors to proper HTTP responses
- Returns HTTP 429 (Too Many Requests) when limits are exceeded
- Required because axum services must have `Infallible` error types

#### BufferLayer
- Required when using `RateLimitLayer` because rate limiting services are not inherently `Clone`
- Axum requires services to be `Clone` for sharing across requests
- Buffer size (1024) determines concurrent request capacity

### Why Rate Limiting Before Authentication?

Rate limiting is applied before authentication because:
- Protects against attacks targeting the authentication system itself
- Prevents excessive load from invalid authentication attempts
- Reduces computational overhead from JWT verification on rate-limited requests

## Tower Rate Limiting Features

### Built-in Benefits
- **Memory Efficient**: Uses efficient algorithms for tracking request counts
- **Thread Safe**: Designed for concurrent access across multiple threads
- **Production Ready**: Battle-tested in real-world applications
- **No External Dependencies**: Works entirely in-memory

### Rate Limiting Algorithm
Tower's `RateLimitLayer` uses a token bucket algorithm:
- Each time window starts with a full bucket of tokens
- Each request consumes one token
- When the bucket is empty, requests are rejected with HTTP 429
- The bucket refills completely at the start of each new time window

## Production Considerations

### Scalability
For distributed systems, consider:
- Redis-based rate limiting with libraries like `tower-governor`
- Consistent rate limiting across multiple instances
- Different limits for different user tiers or API keys

### Error Handling
- Customize the 429 response with proper error messages
- Implement exponential backoff suggestions in rate limit headers
- Log rate limit violations for monitoring

### Security
- Combine with other security measures (CAPTCHA, account lockout)
- Consider IP-based rate limiting for additional protection
- Monitor and alert on unusual rate limit patterns

### Performance
- Rate limiting adds minimal overhead (~microseconds per request)
- Memory usage scales with the number of concurrent clients
- Consider cleanup strategies for long-running applications

## Advanced Usage

### Custom Rate Limit Responses
```rust
// You can customize the rate limit exceeded response
.layer(ServiceBuilder::new()
    .layer(HandleErrorLayer::new(|error: BoxError| async move {
        // Customize the error response
        (StatusCode::TOO_MANY_REQUESTS, "Custom rate limit message")
    }))
    .layer(BufferLayer::new(1024))
    .layer(RateLimitLayer::new(10, Duration::from_secs(60)))
)
```

### Different Limits by User Type
```rust
// You could implement user-tier based rate limiting
let rate_limit = if user.is_premium() { 
    RateLimitLayer::new(100, Duration::from_secs(60))
} else { 
    RateLimitLayer::new(20, Duration::from_secs(60))
};
```

## Related Examples

- [`simple-usage`](../simple-usage/) - Basic axum-gate setup
- [`distributed`](../distributed/) - Distributed authentication setup

## Dependencies

- `tower` - Rate limiting middleware (`limit`, `buffer`, `timeout`, `util` features)
- `tower-http` - HTTP-specific middleware (`trace` feature)
- `axum-gate` - Authentication and authorization
- `tokio` - Async runtime

Note: The `axum-extra` dependency is not needed since `CookieJar` is re-exported by axum-gate.

This example demonstrates how axum-gate integrates seamlessly with tower's ecosystem to build robust, production-ready applications with proper rate limiting protections using industry-standard middleware.