import { Injectable } from '@angular/core';
import {CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, UrlTree, Router} from '@angular/router';
import { Observable } from 'rxjs';
import {TokenService} from './token.service';

/**
 * Class for checking if a user is authenticated or not.
 * If a user is not logged in this will prevent access to home page.
 */

@Injectable()
export class TokenGuard implements CanActivate {

    // Creating instances of tokenService router classes
    constructor(private tokenService: TokenService,
                private router: Router) {}

    /**
     * Checks to see if a user is authenticated.
     */
    canActivate(): boolean {
        if (!this.tokenService.isAuthenticated()){
            this.router.navigate(['login']);
            return false;

        }
        return true;
    }

}
