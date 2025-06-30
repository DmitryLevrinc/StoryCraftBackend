import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from 'src/modules/deffault/prisma/prisma.service';
import { User } from '@prisma/client';
import { JwtPayload } from 'src/common/types';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private prisma: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET || 'yourSecretKey',
      passReqToCallback: true, // Включаем передачу request в validate
    });
  }

  async validate(req: any, payload: JwtPayload): Promise<User> {
    try {
      const userId = payload.sub || payload.id;
      if (!userId) {
        throw new UnauthorizedException('Invalid token');
      }

      // Извлекаем токен из заголовка
      const token = req?.headers?.authorization?.split(' ')[1];
      if (!token) {
        throw new UnauthorizedException('No token provided');
      }

      // Проверяем, не отозван ли токен
      const revokedToken = await this.prisma.revokedToken.findUnique({
        where: { token },
      });

      if (revokedToken) {
        throw new UnauthorizedException('Token has been revoked');
      }

      // Проверяем существование пользователя
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      return user;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('Invalid token');
    }
  }
}