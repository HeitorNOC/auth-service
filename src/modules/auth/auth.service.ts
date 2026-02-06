import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '@/prisma/prisma.service';
import { Prisma } from '@prisma/client';
import { PasswordService } from './services/password.service';
import { TokenService } from './services/token.service';
import { GoogleAuthService } from './services/google-auth.service';
import { LoginAttemptService } from './services/login-attempt.service';
import { LoginDto, RegisterDto, GoogleAuthDto } from './dto';
import { AuthResponse, TokenPair } from '@/common/types';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private prisma: PrismaService,
    private passwordService: PasswordService,
    private tokenService: TokenService,
    private googleAuthService: GoogleAuthService,
    private loginAttemptService: LoginAttemptService,
  ) {}

  async login(
    dto: LoginDto,
    metadata: { ipAddress: string; userAgent?: string },
  ): Promise<AuthResponse> {
    const email = dto.email.toLowerCase();

    await this.loginAttemptService.checkLockout(email, metadata.ipAddress);

    const user = await this.prisma.user.findFirst({
      where: { email },
      include: {
        credential: true,
        userRoles: {
          include: { role: true },
        },
      },
    });

    if (!user || !user.credential) {
      await this.loginAttemptService.recordFailedAttempt(
        email,
        metadata.ipAddress,
        metadata.userAgent,
      );
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await this.passwordService.verifyPassword(
      dto.password,
      user.credential.passwordHash,
    );

    if (!isPasswordValid) {
      await this.loginAttemptService.recordFailedAttempt(
        email,
        metadata.ipAddress,
        metadata.userAgent,
        user.id,
      );
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.status !== 'ACTIVE') {
      throw new UnauthorizedException(`Account is ${user.status.toLowerCase()}`);
    }

    await this.loginAttemptService.recordSuccessfulLogin(
      email,
      metadata.ipAddress,
      metadata.userAgent,
      user.id,
    );

    const roles = user.userRoles.map((ur: { role: { name: string } }) => ur.role.name);

    const tokens = await this.tokenService.generateTokenPair(
      user.id,
      user.accountId,
      roles,
      metadata,
    );

    await this.createAuditLog(user.accountId, user.id, 'user.login', 'user', user.id, metadata);

    return {
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
      },
      tokens,
    };
  }

  async register(
    dto: RegisterDto,
    metadata: { ipAddress: string; userAgent?: string },
  ): Promise<AuthResponse> {
    const email = dto.email.toLowerCase();

    return this.prisma.$transaction(async (tx: Prisma.TransactionClient) => {
      let accountId: string;
      let roleId: string | null = null;

      if (dto.invitationToken) {
        const invitation = await tx.invitation.findFirst({
          where: {
            token: dto.invitationToken,
            email,
            status: 'PENDING',
            expiresAt: { gt: new Date() },
          },
        });

        if (!invitation) {
          throw new BadRequestException('Invalid or expired invitation');
        }

        accountId = invitation.accountId;
        roleId = invitation.roleId;

        await tx.invitation.update({
          where: { id: invitation.id },
          data: { status: 'ACCEPTED', acceptedAt: new Date() },
        });
      } else {
        const accountSlug = this.generateAccountSlug(dto.accountName || email);
        const account = await tx.account.create({
          data: {
            name: dto.accountName || `${dto.firstName || email}'s Account`,
            slug: accountSlug,
            status: 'ACTIVE',
          },
        });
        accountId = account.id;

        const ownerRole = await tx.role.create({
          data: {
            accountId,
            name: 'OWNER',
            description: 'Account owner with full access',
            isSystem: true,
          },
        });

        await tx.role.createMany({
          data: [
            { accountId, name: 'ADMIN', description: 'Administrator', isSystem: true },
            { accountId, name: 'WORKER', description: 'Team member', isSystem: true },
            { accountId, name: 'CLIENT', description: 'External client', isSystem: true },
          ],
        });

        roleId = ownerRole.id;
      }

      const existingUser = await tx.user.findUnique({
        where: { accountId_email: { accountId, email } },
      });

      if (existingUser) {
        throw new ConflictException('User already exists in this account');
      }

      await this.passwordService.validatePassword(dto.password, accountId);

      const passwordHash = await this.passwordService.hashPassword(dto.password);

      const user = await tx.user.create({
        data: {
          accountId,
          email,
          firstName: dto.firstName,
          lastName: dto.lastName,
          status: 'ACTIVE',
          emailVerified: false,
        },
      });

      await tx.credential.create({
        data: {
          userId: user.id,
          passwordHash,
          passwordChangedAt: new Date(),
        },
      });

      if (roleId) {
        await tx.userRole.create({
          data: {
            userId: user.id,
            roleId,
          },
        });
      }

      const userRoles = await tx.userRole.findMany({
        where: { userId: user.id },
        include: { role: true },
      });
      const roles = userRoles.map((ur: { role: { name: string } }) => ur.role.name);

      const tokens = await this.tokenService.generateTokenPair(
        user.id,
        accountId,
        roles,
        metadata,
        tx,
      );

      await this.createAuditLog(
        accountId,
        user.id,
        'user.register',
        'user',
        user.id,
        metadata,
        tx,
      );
      return {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
        },
        tokens,
      };
    }, { timeout: 15000 });
  }

  async googleAuth(
    dto: GoogleAuthDto,
    metadata: { ipAddress: string; userAgent?: string },
  ): Promise<AuthResponse> {
    const googleUser = await this.googleAuthService.verifyIdToken(dto.idToken);

    const { userId, accountId, isNewUser } =
      await this.googleAuthService.findOrCreateUserFromGoogle(googleUser, {
        accountId: dto.accountId,
        invitationToken: dto.invitationToken,
      });

    const userRoles = await this.prisma.userRole.findMany({
      where: { userId },
      include: { role: true },
    });
    const roles = userRoles.map((ur: { role: { name: string } }) => ur.role.name);

    const tokens = await this.tokenService.generateTokenPair(userId, accountId, roles, metadata);

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
      },
    });

    const action = isNewUser ? 'user.register.google' : 'user.login.google';
    await this.createAuditLog(accountId, userId, action, 'user', userId, metadata);

    return {
      user: user!,
      tokens,
    };
  }

  async refreshTokens(
    refreshToken: string,
    metadata: { ipAddress: string; userAgent?: string },
  ): Promise<TokenPair> {
    return this.tokenService.refreshTokens(refreshToken, metadata);
  }

  async logout(userId: string, accountId: string, tokenId?: string): Promise<void> {
    if (tokenId) {
      await this.tokenService.blacklistAccessToken(tokenId);
    }

    await this.createAuditLog(accountId, userId, 'user.logout', 'user', userId);
  }

  async logoutAll(userId: string, accountId: string): Promise<void> {
    await this.tokenService.revokeAllUserSessions(userId, 'User logged out from all devices');

    await this.createAuditLog(accountId, userId, 'user.logout.all', 'user', userId);
  }

  private generateAccountSlug(base: string): string {
    const slug = base
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '-')
      .replace(/-+/g, '-')
      .substring(0, 50);
    const suffix = Math.random().toString(36).substring(2, 8);
    return `${slug}-${suffix}`;
  }

  private async createAuditLog(
    accountId: string,
    userId: string,
    action: string,
    resource: string,
    resourceId?: string,
    metadata?: { ipAddress?: string; userAgent?: string },
    db?: Prisma.TransactionClient,
  ): Promise<void> {
    try {
      const prisma = db ?? this.prisma;
      await prisma.auditLog.create({
        data: {
          accountId,
          userId,
          action,
          resource,
          resourceId,
          ipAddress: metadata?.ipAddress,
          userAgent: metadata?.userAgent,
        },
      });
    } catch (error) {
      this.logger.error(`Failed to create audit log: ${error}`);
    }
  }
}
