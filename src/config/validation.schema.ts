import * as Joi from 'joi';

export const validationSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),

  PORT: Joi.number().default(3001),

  DATABASE_URL: Joi.string().required().messages({
    'string.empty': 'DATABASE_URL is required',
  }),

  REDIS_URL: Joi.string().default('redis://localhost:6379'),

  JWT_ACCESS_SECRET: Joi.string().min(32).required().messages({
    'string.min': 'JWT_ACCESS_SECRET must be at least 32 characters',
    'string.empty': 'JWT_ACCESS_SECRET is required',
  }),
  JWT_REFRESH_SECRET: Joi.string().min(64).required().messages({
    'string.min': 'JWT_REFRESH_SECRET must be at least 64 characters',
    'string.empty': 'JWT_REFRESH_SECRET is required',
  }),
  JWT_ACCESS_EXPIRES_IN: Joi.string().default('1d'),
  JWT_REFRESH_EXPIRES_IN: Joi.string().default('7d'),

  GOOGLE_CLIENT_ID: Joi.string().optional().allow(''),
  GOOGLE_CLIENT_SECRET: Joi.string().optional().allow(''),

  CORS_ORIGINS: Joi.string().default('http://localhost:3000'),

  THROTTLE_TTL: Joi.number().default(60000),
  THROTTLE_LIMIT: Joi.number().default(100),
  THROTTLE_AUTH_TTL: Joi.number().default(60000),
  THROTTLE_AUTH_LIMIT: Joi.number().default(10),

  MAX_LOGIN_ATTEMPTS: Joi.number().default(5),
  LOCKOUT_DURATION_MINUTES: Joi.number().default(15),

  INTERNAL_API_KEY: Joi.string().min(32).required().messages({
    'string.min': 'INTERNAL_API_KEY must be at least 32 characters',
    'string.empty': 'INTERNAL_API_KEY is required',
  }),

  PASSWORD_MIN_LENGTH: Joi.number().default(8),
  PASSWORD_REQUIRE_UPPERCASE: Joi.boolean().default(true),
  PASSWORD_REQUIRE_LOWERCASE: Joi.boolean().default(true),
  PASSWORD_REQUIRE_NUMBER: Joi.boolean().default(true),
  PASSWORD_REQUIRE_SPECIAL: Joi.boolean().default(true),
});
