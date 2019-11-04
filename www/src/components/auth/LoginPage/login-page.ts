import { login } from 'lib/auth/session';
import { showDialog } from "lib/components/Dialog";
import { tt } from 'lib/base/translate';
import { Button } from 'lib/components';
import { Component } from 'vue-property-decorator';
import Vue from 'vue';
import template from './login-page.vue';
import "./login.default.less";
import { ResetPasswordRequest } from '../ResetPassword';
import { redirectToQueryParam } from 'src/base/utils';

@Component({
	components: {
		'app-reset-request': ResetPasswordRequest,
		'app-button': Button
	},
	mixins: [template]
})
export default class LoginPage extends Vue {
	name: string = 'Login';
	email: string = '';
	password: string = '';
	errorReason: string = '';
	passwordDisplayType: string = 'password';
	loggingIn: boolean = false;
	showResetPasswordRequest: boolean = false;
	usernameError: boolean = false;
	passwordError: boolean = false;
	tt: (english?: string, ...args: Array<string | number>) => string = tt;

	login() {
		this.loggingIn = true;
		this.errorReason = undefined;
		this.usernameError = false;
		this.passwordError = false;

		const loginSuccess = (json: Object) => {
			this.loggingIn = false;
			redirectToQueryParam();
		};

		const loginFail = (reason: string) => {
			this.loggingIn = false;
			this.errorReason = reason;
			const passwordExpiredRedirect = () => {
				window.location.hash = `#resetpassword=true&passwordexpired=true&identity=${encodeURIComponent(this.email)}`;
				// TODO: handle
				// globals.pageReload();
			};

			if (reason === "Password has expired") {
				showDialog(tt("Please create a new password"), {
					header: tt("Password has expired"),
					primaryButtonText: tt("OK"),
					primaryButtonColour: "primary",
					primaryButtonAction: passwordExpiredRedirect
				});
			} else {
				this.usernameError = this.errorReason === "Identity authorization not found" ||
					this.errorReason === "Identity may not be empty";
				this.passwordError = this.errorReason === "Invalid password" || this.errorReason === "Account locked. Please contact your administrator";
			}
		};
		login(this.email, this.password, loginSuccess, loginFail);
	}
}
