import { Request } from 'express';

export interface JwtPayload {
  sub: string;
  accountId: string;
  roles: string[];
  jti?: string;
  iat?: number;
  exp?: number;
}

export interface RefreshTokenPayload {
  sub: string;
  accountId: string;
  sessionId: string;
  jti: string;
  iat?: number;
  exp?: number;
}

export interface AuthenticatedUser {
  userId: string;
  accountId: string;
  email: string;
  roles: string[];
  permissions: string[];
}

export interface AuthenticatedRequest extends Request {
  user: AuthenticatedUser;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface AuthResponse {
  user: {
    id: string;
    email: string;
    firstName: string | null;
    lastName: string | null;
  };
  tokens: TokenPair;
}

export interface GoogleUserPayload {
  sub: string;
  email: string;
  email_verified: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
}

export interface ResolvedContext {
  userId: string;
  accountId: string;
  roles: string[];
  permissions: string[];
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegistrationData {
  email: string;
  password: string;
  firstName?: string;
  lastName?: string;
  accountId?: string;
  invitationToken?: string;
}

export interface OAuthData {
  provider: 'GOOGLE';
  idToken: string;
  accountId?: string;
  invitationToken?: string;
}
