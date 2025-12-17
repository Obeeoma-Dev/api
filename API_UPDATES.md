# API Updates - Password Reset & Invitation OTP Verification

## New Endpoints Added

### 1. Verify Password Reset OTP
**Endpoint:** `POST /api/v1/auth/verify-password-reset-otp/`

**Purpose:** Verify the OTP code sent for password reset

**Request Body:**
```json
{
  "code": "123456"
}
```

**Response (200 OK):**
```json
{
  "message": "OTP verified successfully. You can now reset your password."
}
```

**Error Responses:**
- `400 Bad Request` - Invalid or expired OTP code

---

### 2. Verify Invitation OTP
**Endpoint:** `POST /api/v1/auth/verify-invitation-otp/`

**Purpose:** Verify the OTP code sent for employee invitation

**Request Body:**
```json
{
  "email": "employee@example.com",
  "code": "123456"
}
```

**Response (200 OK):**
```json
{
  "message": "OTP verified successfully. You can now complete registration."
}
```

**Error Responses:**
- `400 Bad Request` - Invalid email, code, or expired OTP

---

## Testing

**Base URL (Production):** `http://64.225.122.101`

**Base URL (Local):** `http://localhost:8000`

## Notes
- OTP codes are 6 digits
- OTP codes expire after a set time period
- Once verified, the OTP is deleted and cannot be reused
- For invitation OTP, the verified email is stored in the session for registration

## Questions?
Check the full API documentation at: `http://64.225.122.101/api/schema/swagger-ui/`
