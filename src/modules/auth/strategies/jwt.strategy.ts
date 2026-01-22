import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '@/prisma/prisma.service';
import { RedisService } from '@/common/redis/redis.service';
import { JwtPayload, AuthenticatedUser } from '@/common/types';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(
    private configService: ConfigService,
    private prisma: PrismaService,
    private redisService: RedisService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('jwt.accessSecret'),
    });
  }

  async validate(payload: JwtPayload): Promise<AuthenticatedUser> {
    if (payload.jti) {
      const isBlacklisted = await this.redisService.isTokenBlacklisted(payload.jti);
      if (isBlacklisted) {
        this.logger.warn(`Blocked blacklisted token: ${payload.jti}`);
        throw new UnauthorizedException('Token has been revoked');
      }
    }

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: {
        id: true,
        accountId: true,
        email: true,
        status: true,
      },
    });

    if (!user) {
      this.logger.warn(`User not found for token: ${payload.sub}`);
      throw new UnauthorizedException('User not found');
    }

    if (user.accountId !== payload.accountId) {
      this.logger.warn(`Account mismatch for user ${payload.sub}`);
      throw new UnauthorizedException('Invalid token');
    }

    if (user.status !== 'ACTIVE') {
      this.logger.warn(`Inactive user attempted access: ${payload.sub}`);
      throw new UnauthorizedException('Account is not active');
    }

    let permissions = await this.redisService.getCachedUserPermissions(user.id, user.accountId);

    if (!permissions) {
      permissions = await this.fetchUserPermissions(user.id);
      await this.redisService.cacheUserPermissions(user.id, user.accountId, permissions);
    }

    return {
      userId: user.id,
      accountId: user.accountId,
      email: user.email,
      roles: payload.roles,
      permissions,
    };
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
    for (const userRole of userRoles) {
      for (const rp of userRole.role.rolePermissions) {
        permissions.add(rp.permission.code);
      }
    }

    return Array.from(permissions);
  }
}
