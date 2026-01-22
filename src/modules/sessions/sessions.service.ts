import { Injectable, NotFoundException, Logger } from '@nestjs/common';
import { PrismaService } from '@/prisma/prisma.service';
import { RedisService } from '@/common/redis/redis.service';

export interface SessionInfo {
  id: string;
  userAgent: string | null;
  ipAddress: string | null;
  deviceId: string | null;
  isRevoked: boolean;
  createdAt: Date;
  lastUsedAt: Date;
  expiresAt: Date;
  isCurrent: boolean;
}

@Injectable()
export class SessionsService {
  private readonly logger = new Logger(SessionsService.name);

  constructor(
    private prisma: PrismaService,
    private redisService: RedisService,
  ) {}

  async findAllForUser(userId: string, currentSessionId?: string): Promise<SessionInfo[]> {
    const sessions = await this.prisma.session.findMany({
      where: { userId, isRevoked: false },
      orderBy: { lastUsedAt: 'desc' },
    });

    return sessions.map((session: {
      id: string;
      userAgent: string | null;
      ipAddress: string | null;
      deviceId: string | null;
      isRevoked: boolean;
      createdAt: Date;
      lastUsedAt: Date;
      expiresAt: Date;
    }) => ({
      id: session.id,
      userAgent: session.userAgent,
      ipAddress: session.ipAddress,
      deviceId: session.deviceId,
      isRevoked: session.isRevoked,
      createdAt: session.createdAt,
      lastUsedAt: session.lastUsedAt,
      expiresAt: session.expiresAt,
      isCurrent: session.id === currentSessionId,
    }));
  }

  async revokeSession(sessionId: string, userId: string, reason?: string): Promise<void> {
    const session = await this.prisma.session.findFirst({
      where: { id: sessionId, userId },
    });

    if (!session) {
      throw new NotFoundException('Session not found');
    }

    await this.prisma.session.update({
      where: { id: sessionId },
      data: {
        isRevoked: true,
        revokedAt: new Date(),
        revokedReason: reason || 'User revoked session',
      },
    });

    this.logger.log(`Session ${sessionId} revoked for user ${userId}`);
  }

  async revokeAllExceptCurrent(
    userId: string,
    currentSessionId: string,
    reason?: string,
  ): Promise<number> {
    const result = await this.prisma.session.updateMany({
      where: {
        userId,
        id: { not: currentSessionId },
        isRevoked: false,
      },
      data: {
        isRevoked: true,
        revokedAt: new Date(),
        revokedReason: reason || 'User revoked all other sessions',
      },
    });

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { accountId: true },
    });

    if (user) {
      await this.redisService.invalidateUserPermissions(userId, user.accountId);
    }

    this.logger.log(`Revoked ${result.count} sessions for user ${userId}`);
    return result.count;
  }

  async revokeAllForUser(userId: string, reason?: string): Promise<number> {
    const result = await this.prisma.session.updateMany({
      where: { userId, isRevoked: false },
      data: {
        isRevoked: true,
        revokedAt: new Date(),
        revokedReason: reason || 'All sessions revoked',
      },
    });

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { accountId: true },
    });

    if (user) {
      await this.redisService.invalidateUserPermissions(userId, user.accountId);
    }

    this.logger.log(`Revoked all ${result.count} sessions for user ${userId}`);
    return result.count;
  }

  async cleanupExpiredSessions(): Promise<number> {
    const result = await this.prisma.session.deleteMany({
      where: {
        OR: [
          { expiresAt: { lt: new Date() } },
          {
            isRevoked: true,
            revokedAt: { lt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
          },
        ],
      },
    });

    this.logger.log(`Cleaned up ${result.count} expired sessions`);
    return result.count;
  }
}
