import { TestBed, getTestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import {TokenService} from './token.service';
import {HTTP_INTERCEPTORS} from '@angular/common/http';
import {BackendInterceptor} from './mock_api';
import {UserService} from '../user.service';

describe('TokenService', () => {
    let injector: TestBed;
    let tokenService: TokenService;
    let userService: UserService;
    let httpMock: HttpTestingController;

    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [HttpClientTestingModule],
            providers: [TokenService, UserService,
                {
                    // Referencing backend interceptor from mock-api
                    provide: HTTP_INTERCEPTORS,
                    useClass: BackendInterceptor,
                    multi: true
                }
            ]
        });

        // Injecting the necessary libraries
        injector = getTestBed();
        tokenService = injector.inject(TokenService);
        userService = injector.inject(UserService);
        httpMock = injector.inject(HttpTestingController);
    });

    afterEach(() => {
        // Method to ensure requests are verified
        httpMock.verify();
    });

    describe('Testing User', () => {
        it('should retrieve users', () => {
            const users = [
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
            ];

            let responseUsers;
            tokenService.getUsers().subscribe(response => {
                console.log('responseUser is here');
                console.log(response);
                responseUsers = response.users;
            });

            expect(responseUsers).toEqual(users);
        });
    });

    /**
     * Testing login, ensures credentials are valid for successful login
     */
    describe('Test Login', () => {
        it('Successful Login', () => {
            // Creating mock body
            const user = {
                email: 'micky@mail.com',
                password: 'qwerty'
            };

            // Creating the anticipated successful response
            const expectedResponse = {
                message: 'Login Successful',
                login: true,
                access_token: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTYxNzAwNTcxNCwianRpIjoiMmJkNTYwMmYtMmVkZi0'
                    + '0N2VlLWIxYTQtZDc1NWYxNmYxODI1IiwibmJmIjoxNjE3MDA1NzE0LCJ0eXBlIjoiYWNjZXNzIiwic3ViIjoiZHlsYW5AZW1haWwuY29tIiwiZXhwIjoxN' +
                    'jE3MDA2NjE0fQ.29oLUEEEHdg1pULcrKNHMwlJLxAcF-P8I6Ml9lEG8lk'
            };

            // Variable for mock API response
            let apiResponse;
            // Then calling the service
            userService.fetchUser(user).subscribe(response => {
                apiResponse = response.response;
            });

            // Testing the various responses to ensure they are valid
            expect(apiResponse.message).toEqual(expectedResponse.message);
            expect(apiResponse.login).toEqual(expectedResponse.login);
            expect(apiResponse.access_token).toEqual(expectedResponse.access_token);
        });

        // Testing for invalid login by assigning an incorrect password to a user
        it('Incorrect password', () => {
            // mock body
            const user = {
                email: 'micky@mail.com',
                password: 'pass123'
            };

            // The anticipated response
            const expectedResponse = {
                message: 'Password is wrong!',
                login: false
            };

            // Variable for mock API response
            let apiResponse;
            // Then calling the service
            userService.fetchUser(user).subscribe(response => {
                console.log(response.response);
                apiResponse = response.response;
            });

            // Testing the various responses
            expect(apiResponse.message).toEqual(expectedResponse.message);
            expect(apiResponse.login).toEqual(expectedResponse.login);
        });

        // Testing for invalid login by testing a user that does not exist
        it('Invalid user test', () => {
            // Mock body
            const user = {
                email: 'ronaldo@dell.com',
                password: 'pass321'
            };

            // Anticipated response
            const expectedResponse = {
                message: 'User does not exist',
                login: false
            };

            // Variable for mock API
            let apiResponse;
            userService.fetchUser(user).subscribe(response => {
                console.log(response.response);
                apiResponse = response.response;
            });

            // Testing the responses
            expect(apiResponse.message).toEqual(expectedResponse.message);
            expect(apiResponse.login).toEqual(expectedResponse.login);
        });
    });


    /**
     *  Testing service to create new user
     */
    describe('Creating New User', () => {
        it('should retrieve last user registered', () => {
            // Creating the body of the new user with required credentials
            const newUser = {
                _id: '911b043287b8gd7u812c1f2',
                email: 'paddy@mail.com',
                password: 'paddy1'
            };

            // Variable containing response data
            let apiPayload;
            userService.addUser(newUser).subscribe(response => {
                apiPayload = response;
            });

            // Testing response
            expect(apiPayload).toEqual(newUser);
        });
    });
});
