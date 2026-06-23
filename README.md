# OAuth2 Spring Authorization Server & Resource Server

A complete implementation of OAuth2 and OpenID Connect using Spring Boot, Spring Security, Spring Authorization Server, and Spring OAuth2 Resource Server.

This project demonstrates how to issue, validate, and authorize JWT access tokens using various OAuth2 grant types while securing REST APIs with role-based access control.

---

## Features

### Authorization Server

* OAuth2 Authorization Server
* JWT Access Token generation
* RSA key pair based token signing
* OpenID Connect (OIDC) support
* Authorization Code Grant
* Authorization Code + PKCE Grant
* Client Credentials Grant
* Refresh Token support
* H2 Database integration
* Custom JWT claims
* Custom user authentication

### Resource Server

* JWT validation using JWK Set URI
* OAuth2 Resource Server support
* Role-based authorization
* Custom JWT to Spring Security role conversion
* Method level security using `@EnableMethodSecurity`

---

## Architecture

```text
Client (Browser/Postman)
            |
            v
+-------------------------+
| Authorization Server    |
| Spring Authorization    |
| Server                  |
+-----------+-------------+
            |
            | Issues JWT
            |
            v
+-------------------------+
| Resource Server         |
| Spring Security OAuth2  |
+-----------+-------------+
            |
            v
       Protected APIs
```

---

## OAuth2 Flows Implemented

### Client Credentials Grant

Used for machine-to-machine communication where no user is involved.

**Flow**

```text
Client
   |
   v
Authorization Server
   |
   v
Access Token
```

---

### Authorization Code Grant

Used by server-side applications where users authenticate through a browser.

**Flow**

```text
User Login
     |
     v
Authorization Code
     |
     v
Access Token
```

---

### Authorization Code + PKCE

Used by public clients such as mobile and SPA applications.

**Flow**

```text
Code Verifier
      |
      v
Code Challenge
      |
      v
Authorization Code
      |
      v
Access Token
```

---

### OpenID Connect (OIDC)

Adds authentication and user identity information on top of OAuth2.

**Tokens Generated**

* Access Token
* Refresh Token
* ID Token

---

## Registered Clients

### Client Credentials Client

```text
Client ID: eazybankapi
```

Supported Grant Type:

* Client Credentials

Scopes:

* ADMIN
* USER

---

### Introspection Client

```text
Client ID: eazybankintrospect
```

Used for:

* Token Introspection

---

### Authorization Code Client

```text
Client ID: rdcoffeeshopclient
```

Supported Grant Types:

* Authorization Code
* Refresh Token

Client Authentication:

* Client Secret Basic
* Client Secret Post

---

### PKCE Client

```text
Client ID: rdpublicclient
```

Supported Grant Types:

* Authorization Code
* Refresh Token

Features:

* PKCE Enabled
* Public Client Support

---

## JWT Customization

The Authorization Server adds custom role information into generated access tokens.

Example:

```json
{
  "roles": [
    "ADMIN",
    "USER"
  ]
}
```

The Resource Server extracts these roles and converts them into Spring Security authorities for authorization.

---

## Security Implementation

### Authorization Server

Responsible for:

* User authentication
* Client authentication
* Authorization Code generation
* Access Token generation
* Refresh Token generation
* JWT signing
* OIDC support

### Resource Server

Responsible for:

* JWT validation
* Role extraction
* Endpoint authorization
* Method level security

---

## Project Structure

```text
src/main/java
│
├── config
│   ├── SecurityConfig
│
├── controller
│
├── entity
│   ├── AuthRequest
│
├── repository
│
├── service
│   ├── MyUserDetailsService
│
├── security
│   ├── JwtToRoleConverter
│   ├── CustomAuthenticationProvider
│
└── AuthserverApplication
```

---

## Running the Project

### Clone Repository

```bash
git clone https://github.com/rajeshdakuri/oauth2-spring_authserver-spring_resourceserver.git
```

### Build Project

```bash
mvn clean install
```

### Run Application

```bash
mvn spring-boot:run
```

---

## Technologies Used

* Java
* Spring Boot
* Spring Security
* Spring Authorization Server
* Spring OAuth2 Resource Server
* Spring Data JPA
* H2 Database
* JWT
* OpenID Connect (OIDC)
* Maven
* Lombok

---

## Learning Objectives

This project was created to gain hands-on experience with:

* OAuth2 Architecture
* OpenID Connect (OIDC)
* Authorization Server
* Resource Server
* JWT Authentication
* PKCE
* Spring Security
* Role-Based Access Control (RBAC)
* Custom JWT Claims

---

## Author

**Rajesh D**
