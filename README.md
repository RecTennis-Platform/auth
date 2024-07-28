# PROJECT: TENITY

A brief description of what the API server does. Component: AUTH

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)

## Installation

Step-by-step instructions for setting up the development environment.

### Prerequisites

List of software and tools required:

- [Node.js](https://nodejs.org/)
- [Yarn](https://yarnpkg.com/)

### Steps

1. Open the repository
2. Navigate to the project directory:
3. Install dependencies:
   ```bash
   $ yarn bootstrap
   ```

## Configuration

Details on environment variables and configuration files.

### Environment Variables

Create a `.env` file in the root of the project and add the following variables:

```plaintext
# Environment
ENVIRONMENT=

# Local ports
SERVER_PORT=

# Frontend URL
FRONTEND_URL=

# Google OAuth
OAUTH_CLIENT_ID=
OAUTH_CLIENT_SECRET=

# Database
DATABASE_URL=

# JWT
JWT_AT_SECRET=
JWT_RT_SECRET=
JWT_VT_SECRET=

JWT_AT_EXPIRES=
JWT_RT_EXPIRES=
JWT_VT_EXPIRES=
```

## Usage

Instructions for running the server

### How to Run

To start the development server:

```bash
$ yarn start:dev
```
