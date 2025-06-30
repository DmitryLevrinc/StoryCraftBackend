import { ExecutionContext, ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { User } from '@prisma/client';
import { UserAuthHelperService } from '../../helpers/services/user-auth.helpers.service';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private userAuthHelperService: UserAuthHelperService) {
    super();
  }

  handleRequest<TUser = User>(
    err: any,
    user: TUser,
  ): TUser {
    if (err || !user) {
      throw err || new UnauthorizedException('Invalid or missing JWT token');
    }

    return user;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // First check if the token is revoked before validating with passport
    const token = this.getTokenFromRequest(context);
    
    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

    const isRevoked = await this.userAuthHelperService.isTokenRevoked(token);
    if (isRevoked) {
      throw new ForbiddenException('Token has been revoked');
    }

    // Then proceed with passport JWT validation
    const canActivate = await super.canActivate(context);
    if (!canActivate) {
      return false;
    }

    return true;
  }

  private getTokenFromRequest(context: ExecutionContext): string {
    const request = context.switchToHttp().getRequest();
    return request?.headers?.authorization?.split(' ')[1] || '';
  }
}