# EMPLOYER API DOCUMENTATION

## Overview
This document lists all API endpoints available for **Employers** to manage their organization, employees, and subscriptions on the Obeeoma platform.

**Base URL**: `http://your-domain.com/api/v1/`

**Authentication**: All employer endpoints require authentication with `IsCompanyAdmin` permission.

---

## 📊 1. ORGANIZATION OVERVIEW

### Get Organization Dashboard Overview
**Endpoint**: `GET /dashboard/organization-overview/`

**Purpose**: Get a comprehensive overview of your organization's workforce and platform usage.

**Returns**:
```json
{
  "summary": {
    "total_employees": 150,
    "wellness_index": 78,
    "active_employees": 142
  },
  "employees": {
    "list": [...],  // 10 most recent employees
    "total": 150
  },
  "engagement_trend": {
    "active": 142,
    "inactive": 8,
    "total": 150
  },
  "feature_usage": {
    "wellness_assessments": 65,  // percentage
    "ai_chatbot": 45,
    "mood_tracking": 72,
    "resource_library": 38
  },
  "mood_trend": [
    {"week": 1, "value": 45},
    {"week": 2, "value": 52},
    ...
  ],
  "notifications": [...]
}
```

**Use Cases**:
- Monitor overall workforce wellness
- Track platform adoption
- View recent organizational activities
- Understand employee engagement patterns

---

## 👥 2. EMPLOYEE MANAGEMENT

### List All Employees
**Endpoint**: `GET /dashboard/employees/`

**Purpose**: Get a list of all employees in your organization.

**Query Parameters**:
- `search` - Search by name, email, or department
- `department` - Filter by department name
- `status` - Filter by status (active, inactive, suspended)
- `ordering` - Sort by field (first_name, email, joined_date, status)

**Examples**:
```
GET /dashboard/employees/
GET /dashboard/employees/?search=john
GET /dashboard/employees/?department=Engineering
GET /dashboard/employees/?status=active
GET /dashboard/employees/?ordering=-joined_date
```

**Returns**:
```json
{
  "count": 150,
  "results": [
    {
      "id": 1,
      "first_name": "John",
      "last_name": "Doe",
      "email": "john.doe@company.com",
      "department": "Engineering",
      "status": "active",
      "joined_date": "2025-01-15T10:30:00Z"
    },
    ...
  ]
}
```

### Get Single Employee
**Endpoint**: `GET /dashboard/employees/{id}/`

**Purpose**: Get detailed information about a specific employee.

### Create New Employee
**Endpoint**: `POST /dashboard/employees/`

**Purpose**: Add a new employee to your organization.

**Request Body**:
```json
{
  "first_name": "Jane",
  "last_name": "Smith",
  "email": "jane.smith@company.com",
  "department": 1,
  "status": "active"
}
```

### Update Employee
**Endpoint**: `PUT /dashboard/employees/{id}/`
**Endpoint**: `PATCH /dashboard/employees/{id}/`

**Purpose**: Update employee information.

### Delete Employee
**Endpoint**: `DELETE /dashboard/employees/{id}/`

**Purpose**: Remove an employee from the system.

---

## 🏢 3. DEPARTMENT MANAGEMENT

### List All Departments
**Endpoint**: `GET /dashboard/departments/`

**Purpose**: Get a list of all departments in your organization.

**Query Parameters**:
- `search` - Search by department name
- `ordering` - Sort by name or created_at

**Returns**:
```json
{
  "count": 8,
  "results": [
    {
      "id": 1,
      "name": "Engineering",
      "employee_count": 45,
      "at_risk": false,
      "created_at": "2025-01-01T00:00:00Z"
    },
    ...
  ]
}
```

### Create Department
**Endpoint**: `POST /dashboard/departments/`

**Request Body**:
```json
{
  "name": "Marketing"
}
```

### Update Department
**Endpoint**: `PUT /dashboard/departments/{id}/`
**Endpoint**: `PATCH /dashboard/departments/{id}/`

### Delete Department
**Endpoint**: `DELETE /dashboard/departments/{id}/`

---

## 💳 4. SUBSCRIPTION MANAGEMENT

### Get Current Subscription
**Endpoint**: `GET /dashboard/subscriptions/current/`

**Purpose**: View your organization's current active subscription.

**Returns**:
```json
{
  "id": 1,
  "plan": "enterprise",
  "amount": 499.99,
  "seats": 100,
  "used_seats": 75,
  "available_seats": 25,
  "start_date": "2025-01-01",
  "end_date": "2026-01-01",
  "renewal_date": "2026-01-01",
  "is_active": true,
  "payment_method": {
    "card_type": "Visa",
    "last_four_digits": "4242"
  }
}
```

**Use Cases**:
- Check available employee seats
- Monitor subscription status
- Plan for renewals
- Track usage

### Get Available Plans
**Endpoint**: `GET /dashboard/subscriptions/plans/`

**Purpose**: Browse all available subscription plans.

**Returns**:
```json
[
  {
    "id": 1,
    "name": "starter",
    "display_name": "Starter Plan",
    "price": 99.99,
    "seats": 50,
    "description": "Perfect for small teams",
    "features": [
      "Basic wellness assessments",
      "AI chatbot support",
      "Resource library access",
      "Email support"
    ]
  },
  {
    "id": 2,
    "name": "enterprise",
    "display_name": "Enterprise Plan",
    "price": 499.99,
    "seats": 500,
    "description": "For growing organizations",
    "features": [
      "All Starter features",
      "Advanced analytics",
      "Priority support",
      "Custom integrations",
      "Dedicated account manager"
    ]
  }
]
```

### Get Billing History
**Endpoint**: `GET /dashboard/subscriptions/billing-history/`

**Purpose**: View past invoices and payment records.

**Returns**:
```json
[
  {
    "id": 1,
    "invoice_number": "INV-2025-001",
    "amount": 499.99,
    "plan_name": "Enterprise Plan",
    "billing_date": "2025-01-01",
    "status": "paid",
    "created_at": "2025-01-01T00:00:00Z"
  },
  ...
]
```

### List All Subscriptions
**Endpoint**: `GET /dashboard/subscriptions/`

**Purpose**: View subscription history.

### Update Subscription
**Endpoint**: `PUT /dashboard/subscriptions/{id}/`
**Endpoint**: `PATCH /dashboard/subscriptions/{id}/`

**Purpose**: Modify subscription details (upgrade/downgrade).

---

## 📈 5. ANALYTICS & INSIGHTS

### Get Wellness Reports
**Endpoint**: `GET /dashboard/wellness-reports/`

**Purpose**: View comprehensive wellness analytics for your organization.

**Returns**:
```json
{
  "common_issues": 5,
  "resource_engagement": 120,
  "average_wellbeing_trend": 7.5,
  "at_risk": 2,
  "chat_engagement": [...],
  "department_contributions": [...],
  "recent_activities": [...]
}
```

### Get Tests by Type
**Endpoint**: `GET /dashboard/tests-by-type/`

**Purpose**: View assessment statistics grouped by type (GAD-7, PHQ-9).

### Get Tests by Department
**Endpoint**: `GET /dashboard/tests-by-department/`

**Purpose**: View assessment statistics grouped by department.

---

## ⚙️ 6. ORGANIZATION SETTINGS

### Get Organization Settings
**Endpoint**: `GET /dashboard/settings/`

**Purpose**: View organization preferences and configurations.

**Returns**:
```json
{
  "id": 1,
  "organization_name": "Acme Corp",
  "email_address": "admin@acme.com",
  "anonymize_data": true,
  "enhanced_privacy": false,
  "data_retention_days": 90,
  "weekly_reports": true,
  "browser_notifications": true,
  "report_generation_notifications": true
}
```

### Update Organization Settings
**Endpoint**: `PUT /dashboard/settings/{id}/`
**Endpoint**: `PATCH /dashboard/settings/{id}/`

**Purpose**: Update organization preferences.

**Request Body**:
```json
{
  "organization_name": "Acme Corporation",
  "weekly_reports": false,
  "data_retention_days": 180
}
```

---

## 📧 7. EMPLOYEE INVITATIONS

### Send Employee Invitation
**Endpoint**: `POST /invitations/`

**Purpose**: Invite a new employee to join your organization.

**Request Body**:
```json
{
  "email": "newemployee@company.com",
  "message": "Welcome to our team!"
}
```

**Returns**:
```json
{
  "message": "Invitation sent successfully",
  "invitation": {
    "id": 1,
    "email": "newemployee@company.com",
    "temporary_username": "newemployee1234",
    "expires_at": "2025-11-28T10:00:00Z",
    "created_at": "2025-11-21T10:00:00Z"
  },
  "invitation_link": "/auth/accept-invite/?token=abc123xyz"
}
```

**Note**: The system automatically generates:
- Temporary username
- Temporary password (sent via email)
- Invitation token
- Expiration date (7 days)

### List All Invitations
**Endpoint**: `GET /invitations/`

**Purpose**: View all sent invitations (pending and accepted).

**Returns**:
```json
{
  "count": 5,
  "results": [
    {
      "id": 1,
      "email": "employee@company.com",
      "temporary_username": "employee1234",
      "accepted": false,
      "expires_at": "2025-11-28T10:00:00Z",
      "created_at": "2025-11-21T10:00:00Z"
    },
    ...
  ]
}
```

### Get Single Invitation
**Endpoint**: `GET /invitations/{id}/`

### Delete/Cancel Invitation
**Endpoint**: `DELETE /invitations/{id}/`

**Purpose**: Cancel a pending invitation.

---

## 🔐 AUTHENTICATION

All employer endpoints require authentication. Include the JWT token in the Authorization header:

```
Authorization: Bearer <your_access_token>
```

### Get Access Token
**Endpoint**: `POST /auth/token/`

**Request Body**:
```json
{
  "username": "employer@company.com",
  "password": "your_password"
}
```

**Returns**:
```json
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "username": "employer@company.com",
    "email": "employer@company.com",
    "role": "employer"
  }
}
```

### Refresh Token
**Endpoint**: `POST /auth/token/refresh/`

**Request Body**:
```json
{
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

---

## 📝 COMMON RESPONSE CODES

- `200 OK` - Request successful
- `201 Created` - Resource created successfully
- `204 No Content` - Resource deleted successfully
- `400 Bad Request` - Invalid request data
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error

---

## 💡 BEST PRACTICES

1. **Pagination**: Most list endpoints support pagination. Use `?page=2` to navigate.

2. **Filtering**: Combine multiple filters for precise results:
   ```
   /dashboard/employees/?department=Engineering&status=active&ordering=-joined_date
   ```

3. **Search**: Use the search parameter for quick lookups:
   ```
   /dashboard/employees/?search=john
   ```

4. **Rate Limiting**: Be mindful of API rate limits. Cache responses when possible.

5. **Error Handling**: Always check response status codes and handle errors gracefully.

---

## 🎯 QUICK START GUIDE

### 1. Login and Get Token
```bash
curl -X POST http://your-domain.com/api/v1/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"username": "employer@company.com", "password": "your_password"}'
```

### 2. Get Organization Overview
```bash
curl -X GET http://your-domain.com/api/v1/dashboard/organization-overview/ \
  -H "Authorization: Bearer <your_access_token>"
```

### 3. List Employees
```bash
curl -X GET http://your-domain.com/api/v1/dashboard/employees/ \
  -H "Authorization: Bearer <your_access_token>"
```

### 4. Send Employee Invitation
```bash
curl -X POST http://your-domain.com/api/v1/invitations/ \
  -H "Authorization: Bearer <your_access_token>" \
  -H "Content-Type: application/json" \
  -d '{"email": "newemployee@company.com", "message": "Welcome!"}'
```

### 5. Check Current Subscription
```bash
curl -X GET http://your-domain.com/api/v1/dashboard/subscriptions/current/ \
  -H "Authorization: Bearer <your_access_token>"
```

---

## 📞 SUPPORT

For API support or questions, contact your organization administrator or the Obeeoma support team.

**Documentation Version**: 1.0  
**Last Updated**: November 21, 2025
