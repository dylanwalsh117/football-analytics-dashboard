import { TestBed } from '@angular/core/testing';
import {
    HttpClientTestingModule,
    HttpTestingController,
} from '@angular/common/http/testing';
import { TokenService } from './token.service';
import { TokenInterceptor} from './token.interceptor';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import {UserService} from '../user.service';

/**
 * Class for testing interceptor
 */

describe(`AuthHttpInterceptor`, () => {
    let service: TokenService;
    let httpMock: HttpTestingController;

    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [HttpClientTestingModule],
            providers: [
                TokenService, UserService,
                {
                    // Providing interceptor from TokenInterceptor to be used for testing
                    provide: HTTP_INTERCEPTORS,
                    useClass: TokenInterceptor,
                    multi: true,
                },
            ],
        });

        // Required services for testing
        service = TestBed.get(TokenService);
        httpMock = TestBed.get(HttpTestingController);
    });

    // Testing interceptor for valid authorization header
    it('should add an Authorization header', () => {
        // Calling getUsers service for request
        service.getUsers().subscribe(response => {
            expect(response).toBeTruthy();
        });

        const httpRequest = httpMock.expectOne('http://localhost:5000/user');

        // Testing request for valid authorization request
        expect(httpRequest.request.headers.has('Authorization')).toEqual(true);
    });
});
