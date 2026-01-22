import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '@/prisma/prisma.service';
import { Prisma, AccountStatus } from '@prisma/client';

export interface AccountDetails {
  id: string;
  name: string;
  slug: string;
  status: AccountStatus;
  settings: Record<string, unknown>;
  createdAt: Date;
  userCount: number;
}

export interface UpdateAccountDto {
  name?: string;
  settings?: Record<string, unknown>;
}

@Injectable()
export class AccountsService {
  constructor(private prisma: PrismaService) {}

  async findById(id: string): Promise<AccountDetails> {
    const account = await this.prisma.account.findUnique({
      where: { id },
      include: {
        _count: { select: { users: true } },
      },
    });

    if (!account) {
      throw new NotFoundException('Account not found');
    }

    return this.mapAccountDetails(account);
  }

  async findBySlug(slug: string): Promise<AccountDetails | null> {
    const account = await this.prisma.account.findUnique({
      where: { slug },
      include: {
        _count: { select: { users: true } },
      },
    });

    return account ? this.mapAccountDetails(account) : null;
  }

  async update(id: string, dto: UpdateAccountDto): Promise<AccountDetails> {
    await this.findById(id);

    const account = await this.prisma.account.update({
      where: { id },
      data: {
        name: dto.name,
        settings: dto.settings as Prisma.InputJsonValue,
      },
      include: {
        _count: { select: { users: true } },
      },
    });

    return this.mapAccountDetails(account);
  }

  async getSettings(id: string): Promise<Record<string, unknown>> {
    const account = await this.prisma.account.findUnique({
      where: { id },
      select: { settings: true },
    });

    if (!account) {
      throw new NotFoundException('Account not found');
    }

    return account.settings as Record<string, unknown>;
  }

  async updateSettings(id: string, settings: Record<string, unknown>): Promise<Record<string, unknown>> {
    const currentSettings = await this.getSettings(id);
    const mergedSettings = { ...currentSettings, ...settings };

    await this.prisma.account.update({
      where: { id },
      data: { settings: mergedSettings as Prisma.InputJsonValue },
    });

    return mergedSettings;
  }

  private mapAccountDetails(account: {
    id: string;
    name: string;
    slug: string;
    status: AccountStatus;
    settings: unknown;
    createdAt: Date;
    _count?: { users: number };
  }): AccountDetails {
    return {
      id: account.id,
      name: account.name,
      slug: account.slug,
      status: account.status,
      settings: account.settings as Record<string, unknown>,
      createdAt: account.createdAt,
      userCount: account._count?.users || 0,
    };
  }
}
