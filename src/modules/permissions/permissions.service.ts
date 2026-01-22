import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '@/prisma/prisma.service';
import { Prisma } from '@prisma/client';

type Permission = Prisma.PermissionGetPayload<{}>;

export interface PermissionGroup {
  resource: string;
  permissions: Permission[];
}

@Injectable()
export class PermissionsService {
  private readonly logger = new Logger(PermissionsService.name);

  constructor(private prisma: PrismaService) {}

  async findAll(): Promise<Permission[]> {
    return this.prisma.permission.findMany({
      orderBy: [{ resource: 'asc' }, { action: 'asc' }],
    }) as Promise<Permission[]>;
  }

  async findAllGrouped(): Promise<PermissionGroup[]> {
    const permissions = await this.findAll();

    const grouped = permissions.reduce(
      (acc, perm) => {
        if (!acc[perm.resource]) {
          acc[perm.resource] = [];
        }
        acc[perm.resource].push(perm);
        return acc;
      },
      {} as Record<string, Permission[]>,
    );

    return Object.entries(grouped).map((entry) => {
      const [resource, perms] = entry;
      return {
        resource,
        permissions: perms,
      };
    });
  }

  async findById(id: string): Promise<Permission | null> {
    return this.prisma.permission.findUnique({ where: { id } });
  }

  async findByCode(code: string): Promise<Permission | null> {
    return this.prisma.permission.findUnique({ where: { code } });
  }

  async seedDefaultPermissions(): Promise<void> {
    const defaultPermissions = [
      { code: 'users:view', name: 'View Users', resource: 'users', action: 'view' },
      { code: 'users:create', name: 'Create Users', resource: 'users', action: 'create' },
      { code: 'users:update', name: 'Update Users', resource: 'users', action: 'update' },
      { code: 'users:delete', name: 'Delete Users', resource: 'users', action: 'delete' },
      { code: 'users:manage-roles', name: 'Manage User Roles', resource: 'users', action: 'manage-roles' },
      { code: 'users:deactivate', name: 'Deactivate Users', resource: 'users', action: 'deactivate' },
      { code: 'users:activate', name: 'Activate Users', resource: 'users', action: 'activate' },
      { code: 'roles:view', name: 'View Roles', resource: 'roles', action: 'view' },
      { code: 'roles:create', name: 'Create Roles', resource: 'roles', action: 'create' },
      { code: 'roles:update', name: 'Update Roles', resource: 'roles', action: 'update' },
      { code: 'roles:delete', name: 'Delete Roles', resource: 'roles', action: 'delete' },
      { code: 'roles:manage-permissions', name: 'Manage Role Permissions', resource: 'roles', action: 'manage-permissions' },
      { code: 'account:view', name: 'View Account', resource: 'account', action: 'view' },
      { code: 'account:update', name: 'Update Account', resource: 'account', action: 'update' },
      { code: 'account:manage-settings', name: 'Manage Account Settings', resource: 'account', action: 'manage-settings' },
      { code: 'invitations:view', name: 'View Invitations', resource: 'invitations', action: 'view' },
      { code: 'invitations:create', name: 'Create Invitations', resource: 'invitations', action: 'create' },
      { code: 'invitations:cancel', name: 'Cancel Invitations', resource: 'invitations', action: 'cancel' },
      { code: 'sessions:view', name: 'View Sessions', resource: 'sessions', action: 'view' },
      { code: 'sessions:revoke', name: 'Revoke Sessions', resource: 'sessions', action: 'revoke' },
      { code: 'audit:view', name: 'View Audit Logs', resource: 'audit', action: 'view' },
      { code: 'jobs:view', name: 'View Jobs', resource: 'jobs', action: 'view' },
      { code: 'jobs:create', name: 'Create Jobs', resource: 'jobs', action: 'create' },
      { code: 'jobs:update', name: 'Update Jobs', resource: 'jobs', action: 'update' },
      { code: 'jobs:delete', name: 'Delete Jobs', resource: 'jobs', action: 'delete' },
      { code: 'payments:view', name: 'View Payments', resource: 'payments', action: 'view' },
      { code: 'payments:manage', name: 'Manage Payments', resource: 'payments', action: 'manage' },
      { code: 'clients:view', name: 'View Clients', resource: 'clients', action: 'view' },
      { code: 'clients:create', name: 'Create Clients', resource: 'clients', action: 'create' },
      { code: 'clients:update', name: 'Update Clients', resource: 'clients', action: 'update' },
      { code: 'clients:delete', name: 'Delete Clients', resource: 'clients', action: 'delete' },
    ];

    for (const perm of defaultPermissions) {
      await this.prisma.permission.upsert({
        where: { code: perm.code },
        update: {},
        create: {
          code: perm.code,
          name: perm.name,
          resource: perm.resource,
          action: perm.action,
          description: `Permission to ${perm.action} ${perm.resource}`,
        },
      });
    }

    this.logger.log(`Seeded ${defaultPermissions.length} default permissions`);
  }
}
