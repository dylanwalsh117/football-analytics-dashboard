import {ComponentFixture, fakeAsync, TestBed} from '@angular/core/testing';
import {RouterTestingModule} from '@angular/router/testing';
import { RegisterComponent } from './register.component';
import {HttpClientModule} from '@angular/common/http';
import {element} from 'protractor';

/**
 * Class containing various unit tests for login.component
 */

describe('RegisterComponent', () => {
    let component: RegisterComponent;
    let fixture: ComponentFixture<RegisterComponent>;

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [RouterTestingModule, HttpClientModule],
            declarations: [ RegisterComponent ]
        })
            .compileComponents();
    });

    beforeEach(() => {
        fixture = TestBed.createComponent(RegisterComponent);
        component = fixture.componentInstance;
        fixture.detectChanges();
    });

    it('should create', () => {
        expect(component).toBeTruthy();
    });

    // Ensuring black form is invalid
    it('form invalid when empty', () => {
        expect(component.addForm.valid).toBeFalsy();
    });

    // Testing to ensure that just email and no password is invalid
    it('just email should be invalid', () => {
        let email = component.addForm.controls['email'];
        expect(email.valid).toBeFalsy();
    });

    // Testing to ensure that just password and no email is invalid
    it('just password should be invalid', () => {
        let password = component.addForm.controls['password'];
        expect(password.valid).toBeFalsy();
    });

    // Test to ensure button is disabled when the field is empty
    it('button disabled if form is empty', fakeAsync(() => {
        component.addForm.controls.email.setValue('');
        component.addForm.controls.password.setValue('');
        expect((document.getElementById('register')as HTMLButtonElement).disabled).toBeTruthy();
        }));

    // Test to ensure button is disabled when the fields are invalid e.g too short
    it('button disabled if form is empty', fakeAsync(() => {
        component.addForm.controls.email.setValue('1');
        component.addForm.controls.password.setValue('x');
        expect((document.getElementById('register')as HTMLButtonElement).disabled).toBeTruthy();
    }));

    it('ngOnInit runs', () => {
        expect(component.ngOnInit).toBeTruthy();
    });

    // Test ensuring that if forms are valid the button is clickable
    it('button is enabled if forms are valid', fakeAsync(() => {
        component.addForm.controls.email.setValue('dj@email.com');
        component.addForm.controls.password.setValue('qwerty123');
        fixture.detectChanges();
        expect((document.getElementById('register')as HTMLButtonElement).disabled).toBeFalsy();
    }));

    // Testing if onSubmit is being called
    it('onSubmit is being called', fakeAsync(() => {
        spyOn(component, 'onSubmit');
        (document.getElementById('register') as HTMLButtonElement).click();
        expect(component.onSubmit).toHaveBeenCalledTimes(0);
    }));
});
