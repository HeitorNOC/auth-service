import { Injectable, Logger, ForbiddenException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '@/prisma/prisma.service';
import { RedisService } from '@/common/redis/redis.service';

@Injectable()
export class LoginAttemptService {
  private readonly logger = new Logger(LoginAttemptService.name);
  private readonly maxAttempts: number;
  private readonly lockoutDurationMinutes: number;

  constructor(
    private prisma: PrismaService,
    private redisService: RedisService,
    private configService: ConfigService,
  ) {
    this.maxAttempts = this.configService.get<number>('security.maxLoginAttempts', 5);
    this.lockoutDurationMinutes = this.configService.get<number>(
      'security.lockoutDurationMinutes',
      15,
    );
  }

  async checkLockout(email: string, ipAddress: string): Promise<void> {
    const emailAttempts = await this.redisService.getLoginAttempts(`email:${email}`);
    if (emailAttempts >= this.maxAttempts) {
      this.logger.warn(`Account locked due to too many attempts: ${email}`);
      throw new ForbiddenException({
        message: 'Account temporarily locked',
        lockoutMinutes: this.lockoutDurationMinutes,
        reason: 'Too many failed login attempts',
      });
    }

    const ipAttempts = await this.redisService.getLoginAttempts(`ip:${ipAddress}`);
    if (ipAttempts >= this.maxAttempts * 2) {
      this.logger.warn(`IP locked due to too many attempts: ${ipAddress}`);
      throw new ForbiddenException({
        message: 'Too many login attempts from this IP',
        lockoutMinutes: this.lockoutDurationMinutes,
      });
    }

    const credential = await this.prisma.credential.findFirst({
      where: {
        user: { email: email.toLowerCase() },
        lockedUntil: { gt: new Date() },
      },
    });

    if (credential) {
      const remainingMinutes = Math.ceil(
        (credential.lockedUntil!.getTime() - Date.now()) / (1000 * 60),
      );
      throw new ForbiddenException({
        message: 'Account temporarily locked',
        lockoutMinutes: remainingMinutes,
        reason: 'Too many failed login attempts',
      });
    }
  }

  async recordFailedAttempt(
    email: string,
    ipAddress: string,
    userAgent?: string,
    userId?: string,
  ): Promise<void> {
    await this.redisService.trackLoginAttempt(`email:${email}`);
    await this.redisService.trackLoginAttempt(`ip:${ipAddress}`);

    await this.prisma.loginAttempt.create({
      data: {
        userId,
        email: email.toLowerCase(),
        ipAddress,
        userAgent,
        success: false,
        failureReason: 'Invalid credentials',
      },
    });

    if (userId) {
      const credential = await this.prisma.credential.findUnique({
        where: { userId },
      });

      if (credential) {
        const newAttempts = credential.failedAttempts + 1;
        const updateData: { failedAttempts: number; lockedUntil?: Date } = {
          failedAttempts: newAttempts,
        };

        if (newAttempts >= this.maxAttempts) {
          updateData.lockedUntil = new Date(
            Date.now() + this.lockoutDurationMinutes * 60 * 1000,
          );
          this.logger.warn(`Account locked after ${newAttempts} failed attempts: ${email}`);
        }

        await this.prisma.credential.update({
          where: { userId },
          data: updateData,
        });
      }
    }
  }

  async recordSuccessfulLogin(
    email: string,
    ipAddress: string,
    userAgent?: string,
    userId?: string,
  ): Promise<void> {
    await this.redisService.clearLoginAttempts(`email:${email}`);
    await this.redisService.clearLoginAttempts(`ip:${ipAddress}`);

    await this.prisma.loginAttempt.create({
      data: {
        userId,
        email: email.toLowerCase(),
        ipAddress,
        userAgent,
        success: true,
      },
    });

    if (userId) {
      await this.prisma.credential.update({
        where: { userId },
        data: {
          failedAttempts: 0,
          lockedUntil: null,
        },
      });
    }

    if (userId) {
      await this.prisma.user.update({
        where: { id: userId },
        data: { lastLoginAt: new Date() },
      });
    }
  }

  async getRecentAttempts(
    userId: string,
    limit: number = 10,
  ): Promise<
    {
      success: boolean;
      ipAddress: string;
      userAgent: string | null;
      attemptedAt: Date;
    }[]
  > {
    return this.prisma.loginAttempt.findMany({
      where: { userId },
      orderBy: { attemptedAt: 'desc' },
      take: limit,
      select: {
        success: true,
        ipAddress: true,
        userAgent: true,
        attemptedAt: true,
      },
    });
  }

  async detectSuspiciousActivity(email: string): Promise<boolean> {
    const recentAttempts = await this.prisma.loginAttempt.findMany({
      where: {
        email: email.toLowerCase(),
        attemptedAt: { gte: new Date(Date.now() - 60 * 60 * 1000) },
      },
      select: { ipAddress: true },
    });

    const uniqueIps = new Set(recentAttempts.map((a: { ipAddress: string | null }) => a.ipAddress));
    if (uniqueIps.size > 5) {
      this.logger.warn(`Suspicious activity detected for ${email}: ${uniqueIps.size} unique IPs`);
      return true;
    }

    return false;
  }
}
