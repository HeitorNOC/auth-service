import { Injectable, UnauthorizedException, Logger, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { OAuth2Client } from 'google-auth-library';
import { PrismaService } from '@/prisma/prisma.service';
import { Prisma } from '@prisma/client';
import { GoogleUserPayload } from '@/common/types';

@Injectable()
export class GoogleAuthService {
  private readonly logger = new Logger(GoogleAuthService.name);
  private readonly client: OAuth2Client;

  constructor(
    private configService: ConfigService,
    private prisma: PrismaService,
  ) {
    const clientId = this.configService.get<string>('google.clientId');
    const clientSecret = this.configService.get<string>('google.clientSecret');

    if (clientId && clientSecret) {
      this.client = new OAuth2Client(clientId, clientSecret);
    } else {
      this.logger.warn('Google OAuth is not configured');
      this.client = new OAuth2Client();
    }
  }

  async verifyIdToken(idToken: string): Promise<GoogleUserPayload> {
    try {
      const ticket = await this.client.verifyIdToken({
        idToken,
        audience: this.configService.get<string>('google.clientId'),
      });

      const payload = ticket.getPayload();
      if (!payload) {
        throw new UnauthorizedException('Invalid Google token payload');
      }

      if (!payload.email) {
        throw new BadRequestException('Email not available from Google');
      }

      if (!payload.email_verified) {
        throw new BadRequestException('Google email not verified');
      }

      return {
        sub: payload.sub,
        email: payload.email,
        email_verified: payload.email_verified,
        name: payload.name,
        given_name: payload.given_name,
        family_name: payload.family_name,
        picture: payload.picture,
      };
    } catch (error) {
      this.logger.error(`Google token verification failed: ${error}`);
      throw new UnauthorizedException('Invalid Google token');
    }
  }

  async findOrCreateUserFromGoogle(
    googleUser: GoogleUserPayload,
    options?: {
      accountId?: string;
      invitationToken?: string;
    },
  ): Promise<{ userId: string; accountId: string; isNewUser: boolean }> {
    return this.prisma.$transaction(async (tx: Prisma.TransactionClient) => {
      const existingOAuth = await tx.oAuthAccount.findUnique({
        where: {
          provider_providerAccountId: {
            provider: 'GOOGLE',
            providerAccountId: googleUser.sub,
          },
        },
        include: { user: true },
      });

      if (existingOAuth) {
        return {
          userId: existingOAuth.userId,
          accountId: existingOAuth.user.accountId,
          isNewUser: false,
        };
      }

      let invitation = null;
      if (options?.invitationToken) {
        invitation = await tx.invitation.findFirst({
          where: {
            token: options.invitationToken,
            email: googleUser.email.toLowerCase(),
            status: 'PENDING',
            expiresAt: { gt: new Date() },
          },
        });

        if (!invitation) {
          throw new BadRequestException('Invalid or expired invitation');
        }
      }

      let targetAccountId = options?.accountId || invitation?.accountId;

      if (targetAccountId) {
        const existingUser = await tx.user.findUnique({
          where: {
            accountId_email: {
              accountId: targetAccountId,
              email: googleUser.email.toLowerCase(),
            },
          },
        });

        if (existingUser) {
          await tx.oAuthAccount.create({
            data: {
              userId: existingUser.id,
              provider: 'GOOGLE',
              providerAccountId: googleUser.sub,
              providerEmail: googleUser.email,
              providerData: googleUser as object,
            },
          });

          if (invitation) {
            await tx.invitation.update({
              where: { id: invitation.id },
              data: { status: 'ACCEPTED', acceptedAt: new Date() },
            });
          }

          return {
            userId: existingUser.id,
            accountId: existingUser.accountId,
            isNewUser: false,
          };
        }
      }

      if (!targetAccountId) {
        const newAccount = await tx.account.create({
          data: {
            name: `${googleUser.given_name || googleUser.email}'s Account`,
            slug: this.generateAccountSlug(googleUser.email),
            status: 'ACTIVE',
          },
        });
        targetAccountId = newAccount.id;

        await this.createDefaultRoles(tx, targetAccountId);
      }

      const newUser = await tx.user.create({
        data: {
          accountId: targetAccountId,
          email: googleUser.email.toLowerCase(),
          firstName: googleUser.given_name || null,
          lastName: googleUser.family_name || null,
          status: 'ACTIVE',
          emailVerified: true,
          emailVerifiedAt: new Date(),
        },
      });

      await tx.oAuthAccount.create({
        data: {
          userId: newUser.id,
          provider: 'GOOGLE',
          providerAccountId: googleUser.sub,
          providerEmail: googleUser.email,
          providerData: googleUser as object,
        },
      });

      let roleToAssign = invitation?.roleId;
      if (!roleToAssign) {
        const roleName = !options?.accountId && !invitation ? 'OWNER' : 'WORKER';
        const defaultRole = await tx.role.findFirst({
          where: {
            accountId: targetAccountId,
            name: roleName,
          },
        });
        roleToAssign = defaultRole?.id;
      }

      if (roleToAssign) {
        await tx.userRole.create({
          data: {
            userId: newUser.id,
            roleId: roleToAssign,
          },
        });
      }

      if (invitation) {
        await tx.invitation.update({
          where: { id: invitation.id },
          data: { status: 'ACCEPTED', acceptedAt: new Date() },
        });
      }

      return {
        userId: newUser.id,
        accountId: targetAccountId,
        isNewUser: true,
      };
    });
  }

  private async createDefaultRoles(tx: Prisma.TransactionClient, accountId: string): Promise<void> {
    const defaultRoles = [
      { name: 'OWNER', description: 'Account owner with full access', isSystem: true },
      { name: 'ADMIN', description: 'Administrator with management access', isSystem: true },
      { name: 'WORKER', description: 'Regular team member', isSystem: true },
      { name: 'CLIENT', description: 'External client with limited access', isSystem: true },
    ];

    for (const role of defaultRoles) {
      await tx.role.create({
        data: {
          accountId,
          ...role,
        },
      });
    }
  }

  private generateAccountSlug(email: string): string {
    const base = email.split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '-');
    const suffix = Math.random().toString(36).substring(2, 8);
    return `${base}-${suffix}`;
  }
}
