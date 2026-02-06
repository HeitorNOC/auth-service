import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '@/prisma/prisma.service';
import { RedisService } from '@/common/redis/redis.service';
import { ResolvedContext, JwtPayload } from '@/common/types';

@Injectable()
export class InternalService {
  private readonly logger = new Logger(InternalService.name);

  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
    private prisma: PrismaService,
    private redisService: RedisService,
  ) {}

  async resolveContext(accessToken: string): Promise<ResolvedContext> {
    try {
      const payload = this.jwtService.verify<JwtPayload>(accessToken, {
        secret: this.configService.get<string>('jwt.accessSecret'),
      });

      if (payload.jti) {
        const isBlacklisted = await this.redisService.isTokenBlacklisted(payload.jti);
        if (isBlacklisted) {
          throw new UnauthorizedException('Token has been revoked');
        }
      }

      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
        select: { id: true, accountId: true, status: true },
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      if (user.status !== 'ACTIVE') {
        throw new UnauthorizedException('User account is not active');
      }

      if (user.accountId !== payload.accountId) {
        throw new UnauthorizedException('Token account mismatch');
      }

      let permissions = await this.redisService.getCachedUserPermissions(user.id, user.accountId);

      if (!permissions) {
        permissions = await this.fetchUserPermissions(user.id);
        await this.redisService.cacheUserPermissions(user.id, user.accountId, permissions);
      }

      let roles = await this.redisService.getCachedUserRoles(user.id, user.accountId);

      if (!roles) {
        roles = await this.fetchUserRoles(user.id);
        await this.redisService.cacheUserRoles(user.id, user.accountId, roles);
      }

      return {
        userId: user.id,
        accountId: user.accountId,
        roles,
        permissions,
      };
    } catch (error) {
      this.logger.warn(`Context resolution failed: ${error}`);
      throw new UnauthorizedException('Invalid token');
    }
  }

  async verifyToken(accessToken: string): Promise<{ valid: boolean; user?: { id: string; accountId: string; roles: string[]; permissions: string[] } }> {
    try {
      console.log('[verifyToken] received accessToken:', accessToken);
      const payload = this.jwtService.verify<JwtPayload>(accessToken, {
        secret: this.configService.get<string>('jwt.accessSecret'),
      });
      console.log('[verifyToken] decoded payload:', payload);

      if (payload.jti) {
        const isBlacklisted = await this.redisService.isTokenBlacklisted(payload.jti);
        console.log('[verifyToken] isBlacklisted:', isBlacklisted);
        if (isBlacklisted) {
          return { valid: false };
        }
      }

      // Buscar permissões do usuário
      let permissions = await this.redisService.getCachedUserPermissions(payload.sub, payload.accountId);
      if (!permissions) {
        permissions = await this.fetchUserPermissions(payload.sub);
        await this.redisService.cacheUserPermissions(payload.sub, payload.accountId, permissions);
      }

      return {
        valid: true,
        user: {
          id: payload.sub,
          accountId: payload.accountId,
          roles: payload.roles,
          permissions,
        },
      };
    } catch (error) {
      console.error('[verifyToken] error verifying token:', error);
      return { valid: false };
    }
  }

  async checkPermissions(
    userId: string,
    accountId: string,
    requiredPermissions: string[],
    mode: 'ANY' | 'ALL' = 'ANY',
  ): Promise<boolean> {
    let permissions = await this.redisService.getCachedUserPermissions(userId, accountId);

    if (!permissions) {
      permissions = await this.fetchUserPermissions(userId);
      await this.redisService.cacheUserPermissions(userId, accountId, permissions);
    }

    if (mode === 'ALL') {
      return requiredPermissions.every((p) => permissions!.includes(p));
    }

    return requiredPermissions.some((p) => permissions!.includes(p));
  }

  async checkRoles(userId: string, accountId: string, requiredRoles: string[]): Promise<boolean> {
    let roles = await this.redisService.getCachedUserRoles(userId, accountId);

    if (!roles) {
      roles = await this.fetchUserRoles(userId);
      await this.redisService.cacheUserRoles(userId, accountId, roles);
    }

    return requiredRoles.some((r) => roles!.includes(r));
  }

  async getUserInfo(userId: string, accountId: string) {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, accountId },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        status: true,
      },
    });

    return user || null;
  }

  private async fetchUserPermissions(userId: string): Promise<string[]> {
    const userRoles = await this.prisma.userRole.findMany({
      where: { userId },
      include: {
        role: {
          include: {
            rolePermissions: {
              include: { permission: true },
            },
          },
        },
      },
    });

    const permissions = new Set<string>();
    for (const ur of userRoles) {
      for (const rp of ur.role.rolePermissions) {
        permissions.add(rp.permission.code);
      }
    }

    return Array.from(permissions);
  }

  private async fetchUserRoles(userId: string): Promise<string[]> {
    const userRoles = await this.prisma.userRole.findMany({
      where: { userId },
      include: { role: true },
    });

    return userRoles.map((ur: { role: { name: string } }) => ur.role.name);
  }
}
