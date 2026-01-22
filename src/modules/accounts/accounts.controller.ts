import {
  Controller,
  Get,
  Patch,
  Post,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiParam, ApiQuery } from '@nestjs/swagger';
import { AccountsService, UpdateAccountDto } from './accounts.service';
import { InvitationsService, CreateInvitationDto } from './invitations.service';
import { JwtAuthGuard, RolesGuard, PermissionsGuard } from '@/common/guards';
import { RequirePermissions, CurrentUser, Public } from '@/common/decorators';
import { AuthenticatedUser } from '@/common/types';
import { InvitationStatus } from '@prisma/client';

const INVITATION_STATUS_VALUES = Object.values(InvitationStatus) as string[];

@ApiTags('Account')
@Controller('account')
@UseGuards(JwtAuthGuard, RolesGuard, PermissionsGuard)
@ApiBearerAuth('access-token')
export class AccountsController {
  constructor(
    private readonly accountsService: AccountsService,
    private readonly invitationsService: InvitationsService,
  ) {}

  @Get()
  @RequirePermissions('account:view')
  @ApiOperation({ summary: 'Get current account details' })
  @ApiResponse({ status: 200 })
  async getAccount(@CurrentUser() user: AuthenticatedUser) {
    return this.accountsService.findById(user.accountId);
  }

  @Patch()
  @RequirePermissions('account:update')
  @ApiOperation({ summary: 'Update account' })
  @ApiResponse({ status: 200 })
  async updateAccount(@CurrentUser() user: AuthenticatedUser, @Body() dto: UpdateAccountDto) {
    return this.accountsService.update(user.accountId, dto);
  }

  @Get('settings')
  @RequirePermissions('account:manage-settings')
  @ApiOperation({ summary: 'Get account settings' })
  @ApiResponse({ status: 200 })
  async getSettings(@CurrentUser() user: AuthenticatedUser) {
    return this.accountsService.getSettings(user.accountId);
  }

  @Patch('settings')
  @RequirePermissions('account:manage-settings')
  @ApiOperation({ summary: 'Update account settings' })
  @ApiResponse({ status: 200 })
  async updateSettings(
    @CurrentUser() user: AuthenticatedUser,
    @Body() settings: Record<string, unknown>,
  ) {
    return this.accountsService.updateSettings(user.accountId, settings);
  }

  @Get('invitations')
  @RequirePermissions('invitations:view')
  @ApiOperation({ summary: 'List invitations' })
  @ApiQuery({ name: 'status', required: false, enum: INVITATION_STATUS_VALUES })
  @ApiResponse({ status: 200 })
  async getInvitations(
    @CurrentUser() user: AuthenticatedUser,
    @Query('status') status?: InvitationStatus,
  ) {
    return this.invitationsService.findAll(user.accountId, { status });
  }

  @Post('invitations')
  @RequirePermissions('invitations:create')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create invitation' })
  @ApiResponse({ status: 201 })
  @ApiResponse({ status: 409 })
  async createInvitation(
    @CurrentUser() user: AuthenticatedUser,
    @Body() dto: CreateInvitationDto,
  ) {
    return this.invitationsService.create(user.accountId, dto, user.userId);
  }

  @Delete('invitations/:id')
  @RequirePermissions('invitations:cancel')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Cancel invitation' })
  @ApiParam({ name: 'id' })
  @ApiResponse({ status: 204 })
  async cancelInvitation(@CurrentUser() user: AuthenticatedUser, @Param('id') id: string) {
    await this.invitationsService.cancel(id, user.accountId);
  }

  @Post('invitations/:id/resend')
  @RequirePermissions('invitations:create')
  @ApiOperation({ summary: 'Resend invitation' })
  @ApiParam({ name: 'id' })
  @ApiResponse({ status: 200 })
  async resendInvitation(@CurrentUser() user: AuthenticatedUser, @Param('id') id: string) {
    return this.invitationsService.resend(id, user.accountId);
  }

  @Get('invitations/validate/:token')
  @Public()
  @ApiOperation({ summary: 'Validate invitation token' })
  @ApiParam({ name: 'token' })
  @ApiResponse({ status: 200 })
  async validateInvitation(@Param('token') token: string) {
    return this.invitationsService.validateToken(token);
  }
}
