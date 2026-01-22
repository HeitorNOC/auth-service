import { Module } from '@nestjs/common';
import { AccountsController } from './accounts.controller';
import { AccountsService } from './accounts.service';
import { InvitationsService } from './invitations.service';

@Module({
  controllers: [AccountsController],
  providers: [AccountsService, InvitationsService],
  exports: [AccountsService, InvitationsService],
})
export class AccountsModule {}
