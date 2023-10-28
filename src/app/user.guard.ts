// user.guard.ts
import { Injectable } from '@angular/core';
import { CanActivate } from '@angular/router';
import { AuthService } from './auth.service';

@Injectable({
  providedIn: 'root',
})
export class UserGuard implements CanActivate {
  constructor(private authService: AuthService) {}

  canActivate(): boolean {
    return !this.authService.isUserAdmin();
  }
}
