import { TestBed} from '@angular/core/testing';
import {
    HttpClientTestingModule,
} from '@angular/common/http/testing';
import { TokenGuard} from './token.guard';
import {RouterTestingModule} from '@angular/router/testing';
import {TokenService} from './token.service';
import {AppModule} from '../app.module';
import {Router} from '@angular/router';
import {UserService} from '../user.service';

describe('AuthGuard', () => {
    let tokenService: TokenService;
    let userService: UserService;
    let guard: TokenGuard;
    const routerMock = {navigate: jasmine.createSpy('navigate')};

    beforeEach(() => {
        TestBed.configureTestingModule({
            providers: [TokenGuard, {provide: Router, useValue: routerMock}, TokenService],
            imports: [HttpClientTestingModule, RouterTestingModule, AppModule]
        });

        // Injecting necessary services
        tokenService = TestBed.inject(TokenService);
        userService = TestBed.inject(UserService);
        guard = TestBed.inject(TokenGuard);
    });

    // Ensuring a user who has not been authenticated can't access home page and will redirected to login
    it('should redirect an unauthenticated user to the login route', () => {
        expect(guard.canActivate()).toEqual(false);
        expect(routerMock.navigate).toHaveBeenCalledWith(['login']);
    });

    // Ensuring a user who has been authenticated by successfully logging in can access the rest of the app
    it('should allow the authenticated user to access app', () => {
        spyOn(tokenService, 'isAuthenticated').and.returnValue(true);
        expect(guard.canActivate()).toEqual(true);
    });
});
