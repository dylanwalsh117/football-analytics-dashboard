import {Injectable} from '@angular/core';
import {Observable} from 'rxjs';
import {HttpClient, HttpHeaders} from '@angular/common/http';

/**
 * Class containing methods for registering and logging users in
 */
const httpOptions = {
    headers: new HttpHeaders({
        'Content-Type': 'application/json'
    })
};

@Injectable({
    providedIn: 'root'
})

export class UserService {
    constructor(private http: HttpClient) {
    }

    /** Method to login users with right credentials and return token
     * @param user: object
     * @return observable
     */
    fetchUser(user): Observable<any> {
        return this.http.post('http://localhost:5000/auth', user);
    }

    /**
     * Creating new user using API
     * @param user: object
     * @return: observable
     */
    addUser(user): Observable<any>{
        console.log( {user});
        return this.http.post('http://127.0.0.1:5000/user', user);

    }

}

