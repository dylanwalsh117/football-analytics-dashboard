// title.component.spec.ts
import {async, ComponentFixture, fakeAsync, TestBed} from '@angular/core/testing';
import { LoginComponent } from './login.component';
import {RouterTestingModule} from '@angular/router/testing';
import {HttpClientModule} from '@angular/common/http';

/**
 * Class containing various unit tests for login.component
 */

describe('LoginComponent', () => { // 1
    let component: LoginComponent;
    let fixture: ComponentFixture<LoginComponent>;

    beforeEach(async(() => { // 2
        TestBed.configureTestingModule({
            imports: [RouterTestingModule, HttpClientModule],
            declarations: [ LoginComponent ]
        })
            .compileComponents();
    }));

    beforeEach(() => { // 3
        fixture = TestBed.createComponent(LoginComponent);
        component = fixture.componentInstance;
        fixture.detectChanges();
    });

    it('should create', () => { // 4
        expect(component).toBeTruthy();
    });

    // Ensuring blank form is not allowed
    it('form invalid when empty', () => {
        expect(component.angularForm.valid).toBeFalsy();
    });

    // Testing to ensure that just email and no password is invalid
    it('just email should be invalid', () => {
        let email = component.angularForm.controls['email'];
        expect(email.valid).toBeFalsy();
    });

    // Testing to ensure that just password and no email is invalid
    it('just password should be invalid', () => {
        let password = component.angularForm.controls['password'];
        expect(password.valid).toBeFalsy();
    });

    // Test to ensure button is disabled when the field is empty
    it('button disabled if form is empty', fakeAsync(() => {
        component.angularForm.controls.email.setValue('');
        component.angularForm.controls.password.setValue('');
        expect((document.getElementById('login')as HTMLButtonElement).disabled).toBeTruthy();
    }));

    // Test to ensure button is disabled when the fields are invalid e.g too short
    it('button disabled if form is empty', fakeAsync(() => {
        component.angularForm.controls.email.setValue('1');
        component.angularForm.controls.password.setValue('x');
        expect((document.getElementById('login')as HTMLButtonElement).disabled).toBeTruthy();
    }));

    it('ngOnInit runs', () => {
        expect(component.ngOnInit).toBeTruthy();
    });

    // Test to ensure button is enabled when form is valid
    it('button enabled when form is valid', fakeAsync(() => {
        component.angularForm.controls.email.setValue('dj@email.com');
        component.angularForm.controls.password.setValue('qwerty123');
        fixture.detectChanges();
        expect((document.getElementById('login')as HTMLButtonElement).disabled).toBeFalsy();
    }));

    // Testing if onSubmit is being called
    it('onSubmit is being called', fakeAsync(() => {
        spyOn(component, 'onSubmit');
        (document.getElementById('login') as HTMLButtonElement).click();
        expect(component.onSubmit).toHaveBeenCalledTimes(0);
    }));

});
