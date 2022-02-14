import {ComponentFixture, fakeAsync, TestBed, tick, waitForAsync} from '@angular/core/testing';
import { AppComponent } from './app.component';
import {Router, RouterModule} from '@angular/router';
import {HomeComponent} from './home/home.component';
import {LoginComponent} from './login/login.component';
import {RouterTestingModule} from '@angular/router/testing';
import {routes} from './app-routing.module';
import {Location} from '@angular/common';
import {TokenService} from './auth/token.service';
import {TokenGuard} from './auth/token.guard';
import {HttpClientModule} from '@angular/common/http';
import {MatSnackBarModule} from '@angular/material/snack-bar';

/**
 * Class containing tests for routing
 */
describe('Router: App', () => {

    let location: Location;
    let router: Router;
    let fixture;

    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [RouterTestingModule.withRoutes(routes), HttpClientModule, MatSnackBarModule],
            declarations: [
                HomeComponent,
                LoginComponent,
                AppComponent
            ],
            providers: [
                TokenService,
                TokenGuard
            ]
        });

        // Services to be injected
        router = TestBed.inject(Router);
        location = TestBed.inject(Location);
        // Creating fixture
        fixture = TestBed.createComponent(AppComponent);
        // Initialize router navigation
        router.initialNavigation();
    });

    // Testing if defualted route is /login
    it('"" is defaulted to /login', fakeAsync(() => {
        router.navigate(['']);
        tick();
        expect(location.path()).toBe('/login');
        }));

    // Ensuring that if user is not authenticated he can't access /home and will be redirected to /login
    it('if unauthenticated /home will redirect to /login', fakeAsync(() => {
        router.navigate(['/home']);
        tick();
        expect(location.path()).toBe('/login');
    }));
});
