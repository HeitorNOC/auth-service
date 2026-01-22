import { Injectable, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '@/prisma/prisma.service';
import { Prisma, PasswordPolicy } from '@prisma/client';

export interface PasswordPolicyConfig {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumber: boolean;
  requireSpecialChar: boolean;
  preventReuse: number;
}

@Injectable()
export class PasswordService {
  private readonly defaultPolicy: PasswordPolicyConfig;
  private readonly saltRounds = 12;

  constructor(
    private prisma: PrismaService,
    private configService: ConfigService,
  ) {
    this.defaultPolicy = {
      minLength: configService.get<number>('passwordPolicy.minLength', 8),
      requireUppercase: configService.get<boolean>('passwordPolicy.requireUppercase', true),
      requireLowercase: configService.get<boolean>('passwordPolicy.requireLowercase', true),
      requireNumber: configService.get<boolean>('passwordPolicy.requireNumber', true),
      requireSpecialChar: configService.get<boolean>('passwordPolicy.requireSpecial', true),
      preventReuse: 5,
    };
  }

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.saltRounds);
  }

  async verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
      return await bcrypt.compare(password, hash);
    } catch {
      return false;
    }
  }

  async getPasswordPolicy(accountId: string): Promise<PasswordPolicyConfig> {
    const policy = await this.prisma.passwordPolicy.findUnique({
      where: { accountId },
    });

    if (!policy) {
      return this.defaultPolicy;
    }

    return {
      minLength: policy.minLength,
      requireUppercase: policy.requireUppercase,
      requireLowercase: policy.requireLowercase,
      requireNumber: policy.requireNumber,
      requireSpecialChar: policy.requireSpecialChar,
      preventReuse: policy.preventReuse,
    };
  }

  async validatePassword(password: string, accountId?: string): Promise<void> {
    const policy = accountId ? await this.getPasswordPolicy(accountId) : this.defaultPolicy;

    const errors: string[] = [];

    if (password.length < policy.minLength) {
      errors.push(`Password must be at least ${policy.minLength} characters long`);
    }

    if (policy.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (policy.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (policy.requireNumber && !/[0-9]/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (policy.requireSpecialChar && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    const commonPasswords = ['password', '123456', 'qwerty', 'letmein', 'admin'];
    if (commonPasswords.includes(password.toLowerCase())) {
      errors.push('Password is too common');
    }

    if (errors.length > 0) {
      throw new BadRequestException({
        message: 'Password does not meet requirements',
        errors,
      });
    }
  }

  async needsPasswordChange(userId: string, accountId: string): Promise<boolean> {
    const policy = await this.prisma.passwordPolicy.findUnique({
      where: { accountId },
    });

    if (!policy?.maxAgeDays) {
      return false;
    }

    const credential = await this.prisma.credential.findUnique({
      where: { userId },
    });

    if (!credential?.passwordChangedAt) {
      return true;
    }

    const daysSinceChange = Math.floor(
      (Date.now() - credential.passwordChangedAt.getTime()) / (1000 * 60 * 60 * 24),
    );

    return daysSinceChange >= policy.maxAgeDays;
  }

  async updatePasswordPolicy(
    accountId: string,
    policy: Partial<PasswordPolicyConfig>,
  ): Promise<PasswordPolicy> {
    return this.prisma.passwordPolicy.upsert({
      where: { accountId },
      update: {
        minLength: policy.minLength,
        requireUppercase: policy.requireUppercase,
        requireLowercase: policy.requireLowercase,
        requireNumber: policy.requireNumber,
        requireSpecialChar: policy.requireSpecialChar,
        preventReuse: policy.preventReuse,
      },
      create: {
        accountId,
        minLength: policy.minLength ?? this.defaultPolicy.minLength,
        requireUppercase: policy.requireUppercase ?? this.defaultPolicy.requireUppercase,
        requireLowercase: policy.requireLowercase ?? this.defaultPolicy.requireLowercase,
        requireNumber: policy.requireNumber ?? this.defaultPolicy.requireNumber,
        requireSpecialChar: policy.requireSpecialChar ?? this.defaultPolicy.requireSpecialChar,
        preventReuse: policy.preventReuse ?? this.defaultPolicy.preventReuse,
      },
    });
  }
}
