import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { v4 as uuidv4 } from 'uuid';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '@/prisma/prisma.service';
import { RedisService } from '@/common/redis/redis.service';
import { JwtPayload, RefreshTokenPayload, TokenPair } from '@/common/types';
import { Prisma } from '@prisma/client';

@Injectable()
export class TokenService {
  private readonly logger = new Logger(TokenService.name);
  private readonly saltRounds = 10;

  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
    private prisma: PrismaService,
    private redisService: RedisService,
  ) {}

  async generateTokenPair(
    userId: string,
    accountId: string,
    roles: string[],
    metadata?: { userAgent?: string; ipAddress?: string; deviceId?: string },
  ): Promise<TokenPair> {
    const sessionId = uuidv4();
    const accessTokenId = uuidv4();
    const refreshTokenId = uuidv4();

    const accessPayload: JwtPayload = {
      sub: userId,
      accountId,
      roles,
      jti: accessTokenId,
    };

    const refreshPayload: RefreshTokenPayload = {
      sub: userId,
      accountId,
      sessionId,
      jti: refreshTokenId,
    };

    const accessToken = this.jwtService.sign(accessPayload, {
      secret: this.configService.get<string>('jwt.accessSecret'),
      expiresIn: this.configService.get<string>('jwt.accessExpiresIn', '15m'),
    });

    const refreshToken = this.jwtService.sign(refreshPayload, {
      secret: this.configService.get<string>('jwt.refreshSecret'),
      expiresIn: this.configService.get<string>('jwt.refreshExpiresIn', '7d'),
    });

    const expiresIn = this.parseExpiration(
      this.configService.get<string>('jwt.accessExpiresIn', '15m'),
    );

    const refreshTokenHash = await this.hashToken(refreshToken);

    const refreshExpiresIn = this.parseExpiration(
      this.configService.get<string>('jwt.refreshExpiresIn', '7d'),
    );
    const expiresAt = new Date(Date.now() + refreshExpiresIn * 1000);

    await this.prisma.session.create({
      data: {
        id: sessionId,
        userId,
        accountId,
        refreshTokenHash,
        userAgent: metadata?.userAgent,
        ipAddress: metadata?.ipAddress,
        deviceId: metadata?.deviceId,
        expiresAt,
      },
    });

    return {
      accessToken,
      refreshToken,
      expiresIn,
    };
  }

  async refreshTokens(
    refreshToken: string,
    metadata?: { userAgent?: string; ipAddress?: string },
  ): Promise<TokenPair> {
    try {
      const payload = this.jwtService.verify<RefreshTokenPayload>(refreshToken, {
        secret: this.configService.get<string>('jwt.refreshSecret'),
      });

      const isBlacklisted = await this.redisService.isTokenBlacklisted(payload.jti);
      if (isBlacklisted) {
        throw new UnauthorizedException('Token has been revoked');
      }

      const session = await this.prisma.session.findUnique({
        where: { id: payload.sessionId },
        include: {
          user: {
            include: {
              userRoles: {
                include: { role: true },
              },
            },
          },
        },
      });

      if (!session || session.isRevoked) {
        throw new UnauthorizedException('Session not found or revoked');
      }

      const isValidToken = await this.verifyTokenHash(refreshToken, session.refreshTokenHash);
      if (!isValidToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      if (new Date() > session.expiresAt) {
        await this.revokeSession(session.id, 'Session expired');
        throw new UnauthorizedException('Session expired');
      }

      await this.redisService.blacklistToken(
        payload.jti,
        this.parseExpiration(this.configService.get<string>('jwt.refreshExpiresIn', '7d')),
      );

      const roles = session.user.userRoles.map((ur: { role: { name: string } }) => ur.role.name);

      const newAccessTokenId = uuidv4();
      const newRefreshTokenId = uuidv4();

      const accessPayload: JwtPayload = {
        sub: session.userId,
        accountId: session.accountId,
        roles,
        jti: newAccessTokenId,
      };

      const refreshPayload: RefreshTokenPayload = {
        sub: session.userId,
        accountId: session.accountId,
        sessionId: session.id,
        jti: newRefreshTokenId,
      };

      const newAccessToken = this.jwtService.sign(accessPayload, {
        secret: this.configService.get<string>('jwt.accessSecret'),
        expiresIn: this.configService.get<string>('jwt.accessExpiresIn', '15m'),
      });

      const newRefreshToken = this.jwtService.sign(refreshPayload, {
        secret: this.configService.get<string>('jwt.refreshSecret'),
        expiresIn: this.configService.get<string>('jwt.refreshExpiresIn', '7d'),
      });

      const newRefreshTokenHash = await this.hashToken(newRefreshToken);
      const refreshExpiresIn = this.parseExpiration(
        this.configService.get<string>('jwt.refreshExpiresIn', '7d'),
      );

      await this.prisma.session.update({
        where: { id: session.id },
        data: {
          refreshTokenHash: newRefreshTokenHash,
          lastUsedAt: new Date(),
          userAgent: metadata?.userAgent || session.userAgent,
          ipAddress: metadata?.ipAddress || session.ipAddress,
          expiresAt: new Date(Date.now() + refreshExpiresIn * 1000),
        },
      });

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresIn: this.parseExpiration(
          this.configService.get<string>('jwt.accessExpiresIn', '15m'),
        ),
      };
    } catch (error) {
      this.logger.error(`Token refresh failed: ${error}`);
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async revokeSession(sessionId: string, reason?: string): Promise<void> {
    await this.prisma.session.update({
      where: { id: sessionId },
      data: {
        isRevoked: true,
        revokedAt: new Date(),
        revokedReason: reason,
      },
    });
  }

  async revokeAllUserSessions(userId: string, reason?: string): Promise<void> {
    await this.prisma.session.updateMany({
      where: {
        userId,
        isRevoked: false,
      },
      data: {
        isRevoked: true,
        revokedAt: new Date(),
        revokedReason: reason,
      },
    });

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { accountId: true },
    });

    if (user) {
      await this.redisService.invalidateUserPermissions(userId, user.accountId);
    }
  }

  async blacklistAccessToken(tokenId: string): Promise<void> {
    const ttl = this.parseExpiration(
      this.configService.get<string>('jwt.accessExpiresIn', '15m'),
    );
    await this.redisService.blacklistToken(tokenId, ttl);
  }

  verifyAccessToken(token: string): JwtPayload {
    return this.jwtService.verify<JwtPayload>(token, {
      secret: this.configService.get<string>('jwt.accessSecret'),
    });
  }

  private async hashToken(token: string): Promise<string> {
    return bcrypt.hash(token, this.saltRounds);
  }

  private async verifyTokenHash(token: string, hash: string): Promise<boolean> {
    try {
      return await bcrypt.compare(token, hash);
    } catch {
      return false;
    }
  }

  private parseExpiration(expiration: string): number {
    const match = expiration.match(/^(\d+)([smhd])$/);
    if (!match) {
      return 900;
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
      case 's':
        return value;
      case 'm':
        return value * 60;
      case 'h':
        return value * 3600;
      case 'd':
        return value * 86400;
      default:
        return 900;
    }
  }
}
