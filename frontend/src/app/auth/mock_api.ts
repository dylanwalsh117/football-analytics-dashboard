import {HttpEvent, HttpHandler, HttpInterceptor, HttpRequest, HttpResponse} from '@angular/common/http';
import {Injectable, Injector} from '@angular/core';
import {Observable, of} from 'rxjs';

// Creating body for test users
const usersData = {
    users: [
        {
            _id: '605b0922882b8ff5f812c1f3',
            email: 'micky@mail.com',
            password: 'qwerty'
        },
        {
            _id: '605b091a882b8ff5f812c1f2',
            email: 'ricky@mail',
            password: '123456'
        },
        {
            _id: '605b0913882b8ff5f812c1f1',
            email: 'max@mail.com',
            password: 'password'
        }
    ]
};

@Injectable()
export class BackendInterceptor implements HttpInterceptor {

    constructor(private injector: Injector) {
    }

    /**
     * Function for iterating JSON array
     * @param email: string
     * @param password: string
     */
    searchDb(email, password): string {
        for (const user of usersData.users) {
            if (user.email === email) {
                if (user.password === password) {
                    return 'success';
                } else {
                    return 'wrong_pass';
                }
            }
        }
        return 'wrong_user';
    }

    intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        // GET users API request
        if (request.method === 'GET' && request.url === 'http://localhost:5000/user') {
            return of(new HttpResponse({ body: usersData}));
        }

        // REGISTER USER.
        if (request.method === 'POST' && request.url === 'http://localhost:5000/user') {
            const newUsers = Object.assign([], usersData);
            newUsers.push(request.body);
            return of(new HttpResponse({body: newUsers[newUsers.length - 1]}));
        }

        //  POST request for creating new user
        else if (request.method === 'POST' && request.url === 'http://localhost:5000/auth') {
            // Creating mock responses
            const responses = {
                success: {
                    message: 'Login Successful',
                    login: true,
                    access_token: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTYxNzAwNTcxNCwianRpIjoiMmJkNTYw' +
                        'MmYtMmVkZi00N2VlLWIxYTQtZDc1NWYxNmYxODI1IiwibmJmIjoxNjE3MDA1NzE0LCJ0eXBlIjoiYWNjZXNzIiwic3ViIjoiZHlsYW5AZW1ha' +
                        'WwuY29tIiwiZXhwIjoxNjE3MDA2NjE0fQ.29oLUEEEHdg1pULcrKNHMwlJLxAcF-P8I6Ml9lEG8lk'
                },
                wrong_pass: {
                    message: 'Password is wrong!',
                    login: false
                },
                wrong_user: {
                    message: 'User does not exist',
                    login: false
                },
                error: {
                    message: 'An error has occurred',
                    login: false
                }
            };



            // Using searchDB method to look for the valid user
            const loginCheck = this.searchDb(request.body.email, request.body.password);
            console.log('this is login check', loginCheck);
            console.log(responses[loginCheck]);
            return of(new HttpResponse({body: {response: responses[loginCheck]}}));
        }
        next.handle(request);
    }
}
