import { Injectable, CanActivate, ExecutionContext, ForbiddenException, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PERMISSIONS_KEY, PermissionRequirement } from '../decorators/permissions.decorator';
import { AuthenticatedRequest } from '../types';

@Injectable()
export class PermissionsGuard implements CanActivate {
  private readonly logger = new Logger(PermissionsGuard.name);

  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requirement = this.reflector.getAllAndOverride<PermissionRequirement>(PERMISSIONS_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requirement || requirement.permissions.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const user = request.user;

    if (!user) {
      this.logger.warn('PermissionsGuard: No user found in request');
      throw new ForbiddenException('Access denied');
    }

    const userPermissions = user.permissions || [];
    const requiredPermissions = requirement.permissions;

    let hasPermission: boolean;

    if (requirement.mode === 'ALL') {
      hasPermission = requiredPermissions.every((perm) => userPermissions.includes(perm));
    } else {
      hasPermission = requiredPermissions.some((perm) => userPermissions.includes(perm));
    }

    if (!hasPermission) {
      this.logger.warn(
        `PermissionsGuard: User ${user.userId} lacks required permissions. Required (${requirement.mode}): ${requiredPermissions.join(', ')}. Has: ${userPermissions.join(', ')}`,
      );
      throw new ForbiddenException('Insufficient permissions');
    }

    return true;
  }
}
