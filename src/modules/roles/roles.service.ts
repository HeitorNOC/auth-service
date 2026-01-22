import {
  Injectable,
  NotFoundException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from '@/prisma/prisma.service';
import { RedisService } from '@/common/redis/redis.service';

export interface RoleWithPermissions {
  id: string;
  name: string;
  description: string | null;
  isSystem: boolean;
  permissions: { id: string; code: string; name: string }[];
  userCount: number;
}

export interface CreateRoleDto {
  name: string;
  description?: string;
  permissionIds?: string[];
}

export interface UpdateRoleDto {
  name?: string;
  description?: string;
}

@Injectable()
export class RolesService {
  constructor(
    private prisma: PrismaService,
    private redisService: RedisService,
  ) {}

  async findAll(accountId: string): Promise<RoleWithPermissions[]> {
    const roles = await this.prisma.role.findMany({
      where: { accountId },
      include: {
        rolePermissions: {
          include: { permission: true },
        },
        _count: { select: { userRoles: true } },
      },
      orderBy: { name: 'asc' },
    });

    return roles.map((role: {
      id: string;
      name: string;
      description: string | null;
      isSystem: boolean;
      rolePermissions?: Array<{ permission: { id: string; code: string; name: string } }>;
      _count?: { userRoles: number };
    }) => this.mapRoleWithPermissions(role));
  }

  async findById(id: string, accountId: string): Promise<RoleWithPermissions> {
    const role = await this.prisma.role.findFirst({
      where: { id, accountId },
      include: {
        rolePermissions: {
          include: { permission: true },
        },
        _count: { select: { userRoles: true } },
      },
    });

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    return this.mapRoleWithPermissions(role);
  }

  async create(accountId: string, dto: CreateRoleDto): Promise<RoleWithPermissions> {
    const existingRole = await this.prisma.role.findUnique({
      where: { accountId_name: { accountId, name: dto.name } },
    });

    if (existingRole) {
      throw new ConflictException('Role with this name already exists');
    }

    if (dto.permissionIds?.length) {
      const permissions = await this.prisma.permission.findMany({
        where: { id: { in: dto.permissionIds } },
      });

      if (permissions.length !== dto.permissionIds.length) {
        throw new BadRequestException('One or more permissions not found');
      }
    }

    const role = await this.prisma.role.create({
      data: {
        accountId,
        name: dto.name,
        description: dto.description,
        rolePermissions: dto.permissionIds?.length
          ? {
              create: dto.permissionIds.map((permissionId) => ({ permissionId })),
            }
          : undefined,
      },
      include: {
        rolePermissions: {
          include: { permission: true },
        },
        _count: { select: { userRoles: true } },
      },
    });

    return this.mapRoleWithPermissions(role);
  }

  async update(id: string, accountId: string, dto: UpdateRoleDto): Promise<RoleWithPermissions> {
    const existingRole = await this.findById(id, accountId);

    if (existingRole.isSystem && dto.name && dto.name !== existingRole.name) {
      throw new BadRequestException('Cannot rename system roles');
    }

    if (dto.name && dto.name !== existingRole.name) {
      const duplicateRole = await this.prisma.role.findUnique({
        where: { accountId_name: { accountId, name: dto.name } },
      });

      if (duplicateRole) {
        throw new ConflictException('Role with this name already exists');
      }
    }

    const role = await this.prisma.role.update({
      where: { id },
      data: {
        name: dto.name,
        description: dto.description,
      },
      include: {
        rolePermissions: {
          include: { permission: true },
        },
        _count: { select: { userRoles: true } },
      },
    });

    return this.mapRoleWithPermissions(role);
  }

  async assignPermissions(
    id: string,
    accountId: string,
    permissionIds: string[],
  ): Promise<RoleWithPermissions> {
    await this.findById(id, accountId);

    const permissions = await this.prisma.permission.findMany({
      where: { id: { in: permissionIds } },
    });

    if (permissions.length !== permissionIds.length) {
      throw new BadRequestException('One or more permissions not found');
    }

    await this.prisma.$transaction([
      this.prisma.rolePermission.deleteMany({ where: { roleId: id } }),
      this.prisma.rolePermission.createMany({
        data: permissionIds.map((permissionId) => ({ roleId: id, permissionId })),
      }),
    ]);

    await this.invalidateRoleUsersCache(id, accountId);

    return this.findById(id, accountId);
  }

  async delete(id: string, accountId: string): Promise<void> {
    const role = await this.findById(id, accountId);

    if (role.isSystem) {
      throw new BadRequestException('Cannot delete system roles');
    }

    if (role.userCount > 0) {
      throw new BadRequestException('Cannot delete role with assigned users');
    }

    await this.prisma.role.delete({ where: { id } });
  }

  private async invalidateRoleUsersCache(roleId: string, accountId: string): Promise<void> {
    const userRoles = await this.prisma.userRole.findMany({
      where: { roleId },
      select: { userId: true },
    });

    for (const ur of userRoles) {
      await this.redisService.invalidateUserPermissions(ur.userId, accountId);
    }
  }

  private mapRoleWithPermissions(role: {
    id: string;
    name: string;
    description: string | null;
    isSystem: boolean;
    rolePermissions?: Array<{ permission: { id: string; code: string; name: string } }>;
    _count?: { userRoles: number };
  }): RoleWithPermissions {
    return {
      id: role.id,
      name: role.name,
      description: role.description,
      isSystem: role.isSystem,
      permissions:
        role.rolePermissions?.map((rp) => ({
          id: rp.permission.id,
          code: rp.permission.code,
          name: rp.permission.name,
        })) || [],
      userCount: role._count?.userRoles || 0,
    };
  }
}
