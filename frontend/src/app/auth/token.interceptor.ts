import { Injectable } from '@angular/core';
import {
    HttpRequest,
    HttpHandler,
    HttpEvent,
    HttpInterceptor
} from '@angular/common/http';
import { Observable } from 'rxjs';
import {TokenService} from './token.service';

/**
 * Class to implement interceptor which intercepts HTTP requests, handles the HTTP request and add headers.
 */
@Injectable()
export class TokenInterceptor implements HttpInterceptor {

    // Creating new Instance of authService class.
    constructor(private tokenService: TokenService) {}

    /**
     * Function to intercept the HTTP request and add header.
     * @param request: HttpRequest
     * @param next: HttpHandler
     */
    intercept(request: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
        request = request.clone({
            setHeaders: {Authorization: `Bearer ${this.tokenService.getToken()}`}
        });
        console.log(request);
        return next.handle(request);

    }
}
