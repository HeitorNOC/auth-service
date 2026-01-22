import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name);
  private client: Redis;

  private readonly KEY_PREFIX = {
    PERMISSIONS: 'auth:permissions:',
    ROLES: 'auth:roles:',
    SESSION: 'auth:session:',
    LOGIN_ATTEMPT: 'auth:login_attempt:',
    TOKEN_BLACKLIST: 'auth:blacklist:',
  };

  private readonly TTL = {
    PERMISSIONS: 300,
    ROLES: 300,
    SESSION: 86400,
    LOGIN_ATTEMPT: 900,
  };

  constructor(private configService: ConfigService) {
    const redisUrl = this.configService.get<string>('redis.url', 'redis://localhost:6379');
    this.client = new Redis(redisUrl, {
      retryStrategy: (times) => Math.min(times * 50, 2000),
      maxRetriesPerRequest: 3,
    });
  }

  async onModuleInit() {
    try {
      await this.client.ping();
      this.logger.log('Redis connection established');
    } catch (error) {
      this.logger.error('Failed to connect to Redis', error);
      throw error;
    }
  }

  async onModuleDestroy() {
    await this.client.quit();
    this.logger.log('Redis connection closed');
  }

  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  async set(key: string, value: string, ttl?: number): Promise<void> {
    if (ttl) {
      await this.client.setex(key, ttl, value);
    } else {
      await this.client.set(key, value);
    }
  }

  async del(key: string): Promise<void> {
    await this.client.del(key);
  }

  async cacheUserPermissions(
    userId: string,
    accountId: string,
    permissions: string[],
  ): Promise<void> {
    const key = `${this.KEY_PREFIX.PERMISSIONS}${accountId}:${userId}`;
    await this.set(key, JSON.stringify(permissions), this.TTL.PERMISSIONS);
  }

  async getCachedUserPermissions(userId: string, accountId: string): Promise<string[] | null> {
    const key = `${this.KEY_PREFIX.PERMISSIONS}${accountId}:${userId}`;
    const cached = await this.get(key);
    return cached ? JSON.parse(cached) : null;
  }

  async invalidateUserPermissions(userId: string, accountId: string): Promise<void> {
    const permKey = `${this.KEY_PREFIX.PERMISSIONS}${accountId}:${userId}`;
    const roleKey = `${this.KEY_PREFIX.ROLES}${accountId}:${userId}`;
    await this.del(permKey);
    await this.del(roleKey);
  }

  async cacheUserRoles(userId: string, accountId: string, roles: string[]): Promise<void> {
    const key = `${this.KEY_PREFIX.ROLES}${accountId}:${userId}`;
    await this.set(key, JSON.stringify(roles), this.TTL.ROLES);
  }

  async getCachedUserRoles(userId: string, accountId: string): Promise<string[] | null> {
    const key = `${this.KEY_PREFIX.ROLES}${accountId}:${userId}`;
    const cached = await this.get(key);
    return cached ? JSON.parse(cached) : null;
  }

  async trackLoginAttempt(identifier: string): Promise<number> {
    const key = `${this.KEY_PREFIX.LOGIN_ATTEMPT}${identifier}`;
    const count = await this.client.incr(key);
    if (count === 1) {
      await this.client.expire(key, this.TTL.LOGIN_ATTEMPT);
    }
    return count;
  }

  async getLoginAttempts(identifier: string): Promise<number> {
    const key = `${this.KEY_PREFIX.LOGIN_ATTEMPT}${identifier}`;
    const count = await this.get(key);
    return count ? parseInt(count, 10) : 0;
  }

  async clearLoginAttempts(identifier: string): Promise<void> {
    const key = `${this.KEY_PREFIX.LOGIN_ATTEMPT}${identifier}`;
    await this.del(key);
  }

  async blacklistToken(tokenId: string, ttl: number): Promise<void> {
    const key = `${this.KEY_PREFIX.TOKEN_BLACKLIST}${tokenId}`;
    await this.set(key, '1', ttl);
  }

  async isTokenBlacklisted(tokenId: string): Promise<boolean> {
    const key = `${this.KEY_PREFIX.TOKEN_BLACKLIST}${tokenId}`;
    const result = await this.get(key);
    return result !== null;
  }
}
