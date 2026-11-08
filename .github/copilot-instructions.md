# Login Activity Monitor — Project Instructions

## Project Overview
A Spring Boot REST API application that records login attempts, detects suspicious login behaviour, and provides dashboard statistics.

## Technology Stack
- Java 25
- Spring Boot 4.1.2
- Maven
- Spring Web
- Spring Data JPA
- MySQL 8
- Spring Security
- Lombok
- JUnit and Mockito

## Base Package
`com.pratik.loginmonitor`

## Existing Project Structure
- `config` — SecurityConfig
- `controller` — DashboardController, LoginAttemptController, SuspiciousActivityController
- `dto` — DashboardResponse, LoginRequest
- `entity` — LoginAttempt, SuspiciousActivity
- `enums` — LoginStatus, SuspiciousActivityType
- `repository` — LoginAttemptRepository, SuspiciousActivityRepository
- `service` — DashboardService, DetectionService, LoginService, SuspiciousActivityService

## Existing Features
1. Record login attempts.
2. Capture client IP address.
3. Retrieve login attempts with filters.
4. Detect repeated login failures.
5. Detect successful login after multiple failures.
6. Store suspicious activity records.
7. Retrieve suspicious activity.
8. Dashboard statistics for total, successful, failed, and suspicious attempts.
9. Unit and controller tests.

## Development Rules
- Follow the existing layered architecture.
- Reuse existing classes and methods wherever possible.
- Do not create duplicate services, controllers, repositories, or entities.
- Do not rewrite working features unnecessarily.
- Do not introduce unrelated frameworks or technologies.
- Validate input and handle exceptions properly.
- Keep code readable and explain important changes.
- Do not hardcode database credentials or secrets.
- Run Maven tests after implementing a feature.
- Preserve all existing tests and functionality.

## Git Workflow
- `main` is the stable branch.
- Develop new features on `feature/rate-limiting`.
- Commit and push completed work to the feature branch.
- Merge into main only after testing.

## Current Development Task
Implement login API rate limiting:
- Maximum 5 POST login-attempt requests per IP address per minute.
- The 6th request within the same window must return HTTP 429.
- Each IP address must have its own limit.
- GET endpoints must not be affected.
- Start with an in-memory implementation.
- Add appropriate tests.
- Do not introduce Redis unless explicitly requested.

Before editing, inspect the existing controller, security configuration, and tests. Explain the proposed changes before modifying files.