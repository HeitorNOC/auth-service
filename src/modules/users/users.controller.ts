import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiQuery, ApiParam } from '@nestjs/swagger';
import { UsersService, CreateUserDto, UpdateUserDto } from './users.service';
import { JwtAuthGuard, RolesGuard, PermissionsGuard } from '@/common/guards';
import { Roles, RequirePermissions, CurrentUser } from '@/common/decorators';
import { AuthenticatedUser } from '@/common/types';
import { UserStatus } from '@prisma/client';

const USER_STATUS_VALUES = Object.values(UserStatus) as string[];

@ApiTags('Users')
@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard, PermissionsGuard)
@ApiBearerAuth('access-token')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('me')
  @ApiOperation({ summary: 'Get current user profile' })
  @ApiResponse({ status: 200 })
  async getProfile(@CurrentUser() user: AuthenticatedUser) {
    return this.usersService.getProfile(user.userId, user.accountId);
  }

  @Get()
  @RequirePermissions('users:view')
  @ApiOperation({ summary: 'List users in account' })
  @ApiQuery({ name: 'page', required: false, type: Number })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({ name: 'status', required: false, enum: USER_STATUS_VALUES })
  @ApiQuery({ name: 'search', required: false, type: String })
  @ApiResponse({ status: 200 })
  async findAll(
    @CurrentUser() user: AuthenticatedUser,
    @Query('page') page?: number,
    @Query('limit') limit?: number,
    @Query('status') status?: UserStatus,
    @Query('search') search?: string,
  ) {
    return this.usersService.findAll(user.accountId, { page, limit, status, search });
  }

  @Get(':id')
  @RequirePermissions('users:view')
  @ApiOperation({ summary: 'Get user by ID' })
  @ApiParam({ name: 'id' })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 404 })
  async findOne(@CurrentUser() user: AuthenticatedUser, @Param('id') id: string) {
    return this.usersService.findById(id, user.accountId);
  }

  @Post()
  @RequirePermissions('users:create')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create user' })
  @ApiResponse({ status: 201 })
  @ApiResponse({ status: 409 })
  async create(@CurrentUser() user: AuthenticatedUser, @Body() dto: CreateUserDto) {
    return this.usersService.create(user.accountId, dto, user.userId);
  }

  @Patch(':id')
  @RequirePermissions('users:update')
  @ApiOperation({ summary: 'Update user' })
  @ApiParam({ name: 'id' })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 404 })
  async update(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() dto: UpdateUserDto,
  ) {
    return this.usersService.update(id, user.accountId, dto);
  }

  @Patch(':id/roles')
  @RequirePermissions('users:manage-roles')
  @ApiOperation({ summary: 'Assign roles to user' })
  @ApiParam({ name: 'id' })
  @ApiResponse({ status: 200 })
  async assignRoles(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body('roleIds') roleIds: string[],
  ) {
    return this.usersService.assignRoles(id, user.accountId, roleIds, user.userId);
  }

  @Post(':id/deactivate')
  @RequirePermissions('users:deactivate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Deactivate user' })
  @ApiParam({ name: 'id' })
  @ApiResponse({ status: 200 })
  async deactivate(@CurrentUser() user: AuthenticatedUser, @Param('id') id: string) {
    return this.usersService.deactivate(id, user.accountId);
  }

  @Post(':id/reactivate')
  @RequirePermissions('users:activate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Reactivate user' })
  @ApiParam({ name: 'id' })
  @ApiResponse({ status: 200 })
  async reactivate(@CurrentUser() user: AuthenticatedUser, @Param('id') id: string) {
    return this.usersService.reactivate(id, user.accountId);
  }

  @Delete(':id')
  @RequirePermissions('users:delete')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete user' })
  @ApiParam({ name: 'id' })
  @ApiResponse({ status: 204 })
  async delete(@CurrentUser() user: AuthenticatedUser, @Param('id') id: string) {
    await this.usersService.delete(id, user.accountId);
  }
}
