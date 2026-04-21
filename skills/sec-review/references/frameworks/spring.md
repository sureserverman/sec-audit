# Spring Boot / Spring Security

## Source

- https://docs.spring.io/spring-security/reference/
- https://docs.spring.io/spring-framework/docs/current/reference/html/web.html
- https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html
- https://owasp.org/www-project-top-ten/

## Scope

Covers Spring Boot 2.7.x and 3.x with Spring Security 5.x/6.x, Spring Data
JPA, and Spring Web (RestTemplate / WebClient). Does not cover Spring Batch,
Spring Integration, or reactive WebFlux beyond patterns common to both stacks.

## Dangerous patterns (regex/AST hints)

### SpEL injection via user-controlled expressions — CWE-94

- Why: Evaluating user-controlled strings with `SpelExpressionParser` allows arbitrary Java code execution through SpEL's full expression language.
- Grep: `SpelExpressionParser|ExpressionParser.*parseExpression|StandardEvaluationContext`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://docs.spring.io/spring-framework/docs/current/reference/html/core.html#expressions

### SSRF via RestTemplate/WebClient with user URL — CWE-918

- Why: Passing user-controlled strings directly to `restTemplate.getForObject(url, ...)` or `webClient.get().uri(url)` allows probing internal network services.
- Grep: `restTemplate\.(get|post|exchange|getForObject|postForObject)\(.*req\.|webClient\..*uri\(.*req\.`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

### SQL injection via @Query with string concatenation — CWE-89

- Why: `@Query("SELECT ... WHERE name = '" + param + "'")` or JPQL built with string concatenation bypasses JPA's parameter binding.
- Grep: `@Query\s*\(.*\+\s*\w|nativeQuery.*\+\s*\w|createNativeQuery\s*\(\s*["\'].*\+`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Jackson polymorphic deserialization — CWE-502

- Why: `@JsonTypeInfo` with `As.CLASS` or `enableDefaultTyping()` allows attackers to specify arbitrary Java classes for deserialization, leading to RCE via gadget chains.
- Grep: `enableDefaultTyping|DefaultTyping\.|@JsonTypeInfo.*CLASS|activateDefaultTyping`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

### Spring Boot Actuator endpoints exposed — CWE-200

- Why: Exposing `/actuator/env`, `/actuator/heapdump`, or `/actuator/shutdown` without authentication leaks configuration, secrets, and heap memory or allows remote shutdown.
- Grep: `management\.endpoints\.web\.exposure\.include\s*=\s*\*|management\.endpoint\.shutdown\.enabled\s*=\s*true`
- File globs: `**/application*.properties`, `**/application*.yml`
- Source: https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.endpoints.security

### CSRF disabled without justification — CWE-352

- Why: Calling `.csrf(csrf -> csrf.disable())` or `http.csrf().disable()` removes CSRF protection for all stateful browser-facing endpoints.
- Grep: `csrf\(\)\.disable\(\)|csrf\s*\(\s*csrf\s*->\s*csrf\.disable`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html

## Secure patterns

```java
// Parameterized JPQL — never concatenate
@Query("SELECT u FROM User u WHERE u.email = :email")
Optional<User> findByEmail(@Param("email") String email);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

```java
// Spring Security 6 — correct authorizeHttpRequests ordering
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/public/**").permitAll()
            .anyRequest().authenticated()  // catch-all LAST
        )
        .csrf(Customizer.withDefaults()); // CSRF on by default
    return http.build();
}
```

Source: https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html

```yaml
# application.yml — lock down actuator
management:
  endpoints:
    web:
      exposure:
        include: "health,info"   # never "*" in production
  endpoint:
    health:
      show-details: "when_authorized"
```

Source: https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.endpoints.security

## Fix recipes

### Recipe: Use @Param binding in @Query — addresses CWE-89

**Before (dangerous):**

```java
@Query("SELECT u FROM User u WHERE u.name = '" + name + "'")
List<User> findByName(String name);
```

**After (safe):**

```java
@Query("SELECT u FROM User u WHERE u.name = :name")
List<User> findByName(@Param("name") String name);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Recipe: Disable Jackson default typing — addresses CWE-502

**Before (dangerous):**

```java
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
```

**After (safe):**

```java
ObjectMapper mapper = new ObjectMapper();
// Do NOT call enableDefaultTyping(); use explicit @JsonSubTypes with an
// allowlist if polymorphism is required.
PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
    .allowIfSubType("com.example.model")
    .build();
mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

### Recipe: Restrict Actuator exposure — addresses CWE-200

**Before (dangerous):**

```properties
management.endpoints.web.exposure.include=*
```

**After (safe):**

```properties
management.endpoints.web.exposure.include=health,info
management.endpoint.health.show-details=when_authorized
```

Source: https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.endpoints.security

### Recipe: Fix authorizeHttpRequests ordering — addresses CWE-284

**Before (dangerous):**

```java
auth.anyRequest().authenticated()
    .requestMatchers("/admin/**").hasRole("ADMIN");  // unreachable
```

**After (safe):**

```java
auth.requestMatchers("/admin/**").hasRole("ADMIN")
    .anyRequest().authenticated();  // catch-all last
```

Source: https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html

## Version notes

- Spring Security 6.x: `authorizeRequests()` is deprecated; use `authorizeHttpRequests()`. The ordering rules are the same but the API differs.
- Spring Boot 3.x: Requires Java 17+; `HttpSecurity` lambda DSL is mandatory — the old method-chain style (`http.csrf().disable()`) raises deprecation warnings.
- Spring Boot 2.7 to 3.x migration: `spring.security.oauth2.*` property namespaces changed; review auto-configuration if upgrading.
- Jackson 2.10+: `activateDefaultTyping` with a `PolymorphicTypeValidator` is the safe replacement for the deprecated `enableDefaultTyping`.

## Common false positives

- `csrf().disable()` in `@Configuration` classes annotated `@Profile("test")` — disabled only in test context; verify no prod profile picks it up.
- `SpelExpressionParser` used only on developer-owned annotation-driven expressions (e.g., `@PreAuthorize("hasRole('ADMIN')")`) — safe, not user-controlled.
- `management.endpoints.web.exposure.include=*` when an `@EnableWebSecurity` config restricts the `/actuator/**` path to authenticated `ACTUATOR` role.
- RestTemplate calls to hardcoded, developer-owned URLs with no user-controlled segments — not SSRF.
