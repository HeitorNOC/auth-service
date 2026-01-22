import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { PrismaService } from '@/prisma/prisma.service';
import { Prisma, InvitationStatus } from '@prisma/client';
import { v4 as uuidv4 } from 'uuid';

export interface InvitationDetails {
  id: string;
  email: string;
  status: InvitationStatus;
  roleName: string | null;
  invitedByEmail: string | null;
  expiresAt: Date;
  createdAt: Date;
}

export interface CreateInvitationDto {
  email: string;
  roleId?: string;
}

@Injectable()
export class InvitationsService {
  constructor(private prisma: PrismaService) {}

  async findAll(
    accountId: string,
    options?: { status?: InvitationStatus },
  ): Promise<InvitationDetails[]> {
    const where: { accountId: string; status?: InvitationStatus } = { accountId };
    if (options?.status) {
      where.status = options.status;
    }

    const invitations = await this.prisma.invitation.findMany({
      where,
      orderBy: { createdAt: 'desc' },
    });

    return Promise.all(invitations.map((inv) => this.mapInvitation(inv)));
  }

  async create(
    accountId: string,
    dto: CreateInvitationDto,
    invitedBy: string,
  ): Promise<InvitationDetails> {
    const email = dto.email.toLowerCase();

    const existingUser = await this.prisma.user.findUnique({
      where: { accountId_email: { accountId, email } },
    });

    if (existingUser) {
      throw new ConflictException('User already exists in this account');
    }

    const existingInvitation = await this.prisma.invitation.findFirst({
      where: {
        accountId,
        email,
        status: 'PENDING',
        expiresAt: { gt: new Date() },
      },
    });

    if (existingInvitation) {
      throw new ConflictException('Pending invitation already exists for this email');
    }

    if (dto.roleId) {
      const role = await this.prisma.role.findFirst({
        where: { id: dto.roleId, accountId },
      });
      if (!role) {
        throw new BadRequestException('Role not found');
      }
    }

    const token = `inv_${uuidv4().replace(/-/g, '')}`;
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    const invitation = await this.prisma.invitation.create({
      data: {
        accountId,
        email,
        token,
        roleId: dto.roleId,
        invitedBy,
        expiresAt,
      },
    });

    return this.mapInvitation(invitation);
  }

  async cancel(id: string, accountId: string): Promise<void> {
    const invitation = await this.prisma.invitation.findFirst({
      where: { id, accountId, status: 'PENDING' },
    });

    if (!invitation) {
      throw new NotFoundException('Invitation not found or already processed');
    }

    await this.prisma.invitation.update({
      where: { id },
      data: { status: 'CANCELLED' },
    });
  }

  async resend(id: string, accountId: string): Promise<InvitationDetails> {
    const invitation = await this.prisma.invitation.findFirst({
      where: { id, accountId },
    });

    if (!invitation) {
      throw new NotFoundException('Invitation not found');
    }

    if (invitation.status !== 'PENDING' && invitation.status !== 'EXPIRED') {
      throw new BadRequestException('Can only resend pending or expired invitations');
    }

    const newToken = `inv_${uuidv4().replace(/-/g, '')}`;
    const newExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    const updated = await this.prisma.invitation.update({
      where: { id },
      data: {
        token: newToken,
        expiresAt: newExpiresAt,
        status: 'PENDING',
      },
    });

    return this.mapInvitation(updated);
  }

  async validateToken(token: string): Promise<{
    valid: boolean;
    email?: string;
    accountId?: string;
    accountName?: string;
  }> {
    const invitation = await this.prisma.invitation.findUnique({
      where: { token },
      include: { account: true },
    });

    if (!invitation) {
      return { valid: false };
    }

    if (invitation.status !== 'PENDING') {
      return { valid: false };
    }

    if (new Date() > invitation.expiresAt) {
      await this.prisma.invitation.update({
        where: { id: invitation.id },
        data: { status: 'EXPIRED' },
      });
      return { valid: false };
    }

    return {
      valid: true,
      email: invitation.email,
      accountId: invitation.accountId,
      accountName: invitation.account.name,
    };
  }

  private async mapInvitation(invitation: {
    id: string;
    email: string;
    status: InvitationStatus;
    roleId: string | null;
    invitedBy: string;
    expiresAt: Date;
    createdAt: Date;
  }): Promise<InvitationDetails> {
    let roleName: string | null = null;
    let invitedByEmail: string | null = null;

    if (invitation.roleId) {
      const role = await this.prisma.role.findUnique({
        where: { id: invitation.roleId },
        select: { name: true },
      });
      roleName = role?.name || null;
    }

    const inviter = await this.prisma.user.findUnique({
      where: { id: invitation.invitedBy },
      select: { email: true },
    });
    invitedByEmail = inviter?.email || null;

    return {
      id: invitation.id,
      email: invitation.email,
      status: invitation.status,
      roleName,
      invitedByEmail,
      expiresAt: invitation.expiresAt,
      createdAt: invitation.createdAt,
    };
  }
}
