import {
  Injectable,
  NotFoundException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from '@/prisma/prisma.service';
import { RedisService } from '@/common/redis/redis.service';
import { Prisma, UserStatus } from '@prisma/client';

export interface CreateUserDto {
  email: string;
  firstName?: string;
  lastName?: string;
  roleIds?: string[];
}

export interface UpdateUserDto {
  firstName?: string;
  lastName?: string;
  status?: UserStatus;
}

export interface UserWithRoles {
  id: string;
  accountId: string;
  email: string;
  firstName: string | null;
  lastName: string | null;
  status: UserStatus;
  emailVerified: boolean;
  createdAt: Date;
  lastLoginAt: Date | null;
  roles: { id: string; name: string }[];
}

@Injectable()
export class UsersService {
  constructor(
    private prisma: PrismaService,
    private redisService: RedisService,
  ) {}

  async findById(id: string, accountId: string): Promise<UserWithRoles> {
    const user = await this.prisma.user.findFirst({
      where: { id, accountId },
      include: {
        userRoles: {
          include: { role: true },
        },
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.mapUserWithRoles(user);
  }

  async findByEmail(email: string, accountId: string): Promise<UserWithRoles | null> {
    const user = await this.prisma.user.findUnique({
      where: {
        accountId_email: { accountId, email: email.toLowerCase() },
      },
      include: {
        userRoles: {
          include: { role: true },
        },
      },
    });

    return user ? this.mapUserWithRoles(user) : null;
  }

  async findAll(
    accountId: string,
    options?: {
      page?: number;
      limit?: number;
      status?: UserStatus;
      search?: string;
    },
  ): Promise<{ users: UserWithRoles[]; total: number; page: number; limit: number }> {
    const page = options?.page || 1;
    const limit = Math.min(options?.limit || 20, 100);
    const skip = (page - 1) * limit;

    const where: {
      accountId: string;
      status?: UserStatus;
      OR?: Array<{ email?: object; firstName?: object; lastName?: object }>;
    } = { accountId };

    if (options?.status) {
      where.status = options.status;
    }

    if (options?.search) {
      where.OR = [
        { email: { contains: options.search, mode: 'insensitive' } },
        { firstName: { contains: options.search, mode: 'insensitive' } },
        { lastName: { contains: options.search, mode: 'insensitive' } },
      ];
    }

    const [users, total] = await Promise.all([
      this.prisma.user.findMany({
        where,
        include: {
          userRoles: {
            include: { role: true },
          },
        },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      this.prisma.user.count({ where }),
    ]);

    return {
      users: users.map((u) => this.mapUserWithRoles(u)),
      total,
      page,
      limit,
    };
  }

  async create(accountId: string, dto: CreateUserDto, createdBy?: string): Promise<UserWithRoles> {
    const email = dto.email.toLowerCase();

    const existingUser = await this.prisma.user.findUnique({
      where: { accountId_email: { accountId, email } },
    });

    if (existingUser) {
      throw new ConflictException('User with this email already exists in the account');
    }

    if (dto.roleIds?.length) {
      const roles = await this.prisma.role.findMany({
        where: {
          id: { in: dto.roleIds },
          accountId,
        },
      });

      if (roles.length !== dto.roleIds.length) {
        throw new BadRequestException('One or more roles not found');
      }
    }

    const user = await this.prisma.user.create({
      data: {
        accountId,
        email,
        firstName: dto.firstName,
        lastName: dto.lastName,
        status: 'PENDING_VERIFICATION',
        userRoles: dto.roleIds?.length
          ? {
              create: dto.roleIds.map((roleId) => ({
                roleId,
                assignedBy: createdBy,
              })),
            }
          : undefined,
      },
      include: {
        userRoles: {
          include: { role: true },
        },
      },
    });

    return this.mapUserWithRoles(user);
  }

  async update(id: string, accountId: string, dto: UpdateUserDto): Promise<UserWithRoles> {
    await this.findById(id, accountId);

    const user = await this.prisma.user.update({
      where: { id },
      data: {
        firstName: dto.firstName,
        lastName: dto.lastName,
        status: dto.status,
      },
      include: {
        userRoles: {
          include: { role: true },
        },
      },
    });

    await this.redisService.invalidateUserPermissions(id, accountId);

    return this.mapUserWithRoles(user);
  }

  async assignRoles(
    userId: string,
    accountId: string,
    roleIds: string[],
    assignedBy?: string,
  ): Promise<UserWithRoles> {
    await this.findById(userId, accountId);

    const roles = await this.prisma.role.findMany({
      where: {
        id: { in: roleIds },
        accountId,
      },
    });

    if (roles.length !== roleIds.length) {
      throw new BadRequestException('One or more roles not found');
    }

    await this.prisma.$transaction([
      this.prisma.userRole.deleteMany({ where: { userId } }),
      this.prisma.userRole.createMany({
        data: roleIds.map((roleId) => ({
          userId,
          roleId,
          assignedBy,
        })),
      }),
    ]);

    await this.redisService.invalidateUserPermissions(userId, accountId);

    return this.findById(userId, accountId);
  }

  async deactivate(id: string, accountId: string): Promise<UserWithRoles> {
    return this.update(id, accountId, { status: UserStatus.INACTIVE });
  }

  async reactivate(id: string, accountId: string): Promise<UserWithRoles> {
    return this.update(id, accountId, { status: UserStatus.ACTIVE });
  }

  async delete(id: string, accountId: string): Promise<void> {
    await this.findById(id, accountId);

    await this.prisma.user.delete({ where: { id } });

    await this.redisService.invalidateUserPermissions(id, accountId);
  }

  async getProfile(userId: string, accountId: string): Promise<UserWithRoles> {
    return this.findById(userId, accountId);
  }

  private mapUserWithRoles(user: {
    id: string;
    accountId: string;
    email: string;
    firstName: string | null;
    lastName: string | null;
    status: UserStatus;
    emailVerified: boolean;
    createdAt: Date;
    lastLoginAt: Date | null;
    userRoles?: Array<{ role: { id: string; name: string } }>;
  }): UserWithRoles {
    return {
      id: user.id,
      accountId: user.accountId,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      status: user.status,
      emailVerified: user.emailVerified,
      createdAt: user.createdAt,
      lastLoginAt: user.lastLoginAt,
      roles:
        user.userRoles?.map((ur) => ({
          id: ur.role.id,
          name: ur.role.name,
        })) || [],
    };
  }
}
