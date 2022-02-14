import {Injectable} from '@angular/core';
import {Observable} from 'rxjs';
import {HttpClient, HttpHeaders} from '@angular/common/http';
import { JwtHelperService } from '@auth0/angular-jwt';

/**
 * Class containing methods for JWT authentication
 */

export const httpOptions = {
    headers: new HttpHeaders({
        'Content-Type': 'application/json'
    })
};

@Injectable({
    providedIn: 'root'
})

export class TokenService {
    constructor(private http: HttpClient) {}
    // New instance of JWTHelperService class
    jwtHelper = new JwtHelperService();

    // Getting token from API url
    validateToken(token): Observable<any> {
        return this.http.get('http://127.0.0.1:5000/token');

    }

    /**
     * Token from local storage
     * @return: token
     */
    public getToken(): string{
        return localStorage.getItem('token');
    }

    /**
     * Checking for valid token
     * @return: Boolean
     */
    public isAuthenticated(): boolean {
        const token = localStorage.getItem('token');
        // Check whether the token is expired and return
        // true or false
        return !this.jwtHelper.isTokenExpired(token);
    }
    getUsers(): Observable<any>{
        return this.http.get('http://localhost:5000/user');
    }

}
