import { login } from 'lib/auth/session';
import { Button } from 'lib/components';
import { setPassword, updatePassword, checkPassword } from "src/auth/auth-utils";
import { showDialog, showNotification } from "lib/components/Dialog";
import { tt } from 'lib/base/translate';
import ResetPasswordRequest from "./reset-password-request";
import { logInfo, logTrace } from 'lib/log/logger';
import { isValidPasswordOption, passwordStrength, hasConsecutiveCharacters } from 'src/components/auth/ResetPassword/reset-password-defs';
import { Component, Prop } from 'vue-property-decorator';
import Vue from 'vue';
import template from './reset-password-confirm.vue';

import "./password.default.less";

@Component({
	components: {
		'app-reset-request': ResetPasswordRequest,
		'app-button': Button
	},
	mixins: [template]
})
export default class ResetPasswordConfirm extends Vue {
	name: string = 'ResetPasswordConfirm';
	@Prop(String) welcome: string;
	@Prop(String) identity: string;
	@Prop(String) userid: string;
	@Prop(String) token: string;
	@Prop({ type: Boolean, default: false }) tokenExpired: boolean;
	@Prop({ type: Boolean, default: false }) passwordExpired: boolean;

	loggingIn: boolean = false;
	password: string = '';
	passwordConfirm: string = '';
	currentPassword: string = '';
	showResetPasswordRequest: boolean = false;
	passwordStrengthText: string = null;
	passwordStrengthClass: string = '';
	passwordInvalidError: string = '';
	passwordCurrentError: string = '';
	passwordLowerCaseClass: string = 'password-invalid';
	passwordUpperCaseClass: string = 'password-invalid';
	passwordNumberClass: string = 'password-invalid';
	passwordSpecialCaseClass: string = 'password-invalid';
	passwordNonrepeatingClass: string = 'password-invalid';
	passwordNonconsecutiveClass: string = 'password-invalid';
	passwordLengthClass: string = 'password-invalid';
	passwordNormalLengthClass: string = 'password-invalid';
	currentPasswordErrorClass: string = 'password-invalid-error';
	passwordMatchClass: string = '';
	passwordMatchText: string = '';
	canSubmit: boolean = false;
	passwordIsValid: boolean = false;
	currentPasswordIsValid: boolean = false;
	editingPassword: boolean = false;
	editingConfirm: boolean = false;
	confirmInputType: string = 'password';
	passwordInputType: string = 'password';
	currentInputType: string = 'password';
	enforcePasswordPolicy: boolean = false; // clientConfig.isFeatureActive("enforce-password-policy");
	tt: (english?: string, ...args: Array<string | number>) => string = tt;

	get passwordMatch(): Boolean {
		return this.password.length > 0 && this.password === this.passwordConfirm;
	}

	submitPassword() {
		const loginSuccess = () => {
			logTrace("Post-password reset login successful. Reloading page");
			this.navigateHome();
		};

		const loginFail = (responseText: string) => {
			showNotification("Error", tt("Password successfully reset, but could not login: " + responseText));
		};

		const setPasswordSuccess = () => {
			logInfo('Password successfully reset. Logging in');
			showDialog(tt("Password has successfully been changed"), {
				header: tt("Password Change"),
				primaryButtonText: tt("OK"),
				primaryButtonColour: "primary",
				primaryButtonAction: () => { login(this.identity, this.password, loginSuccess, loginFail); }
			});
		};

		const setPasswordError = (responseText: string) => {
			this.passwordInvalidError = responseText;
		};

		if (!this.passwordMatch) {
			this.passwordInvalidError = "Passwords do not match";
			return;
		}

		if (this.token)
			setPassword(this.userid, this.password, this.token, setPasswordSuccess, setPasswordError);
		else
			updatePassword(this.identity, this.currentPassword, this.password, setPasswordSuccess, setPasswordError);
	}

	validatePassword() {
		this.passwordStrengthText = '';
		this.passwordStrengthClass = '';

		if (this.enforcePasswordPolicy) {
			this.passwordLowerCaseClass = !this.password.match(/[a-z]/g) ? "password-invalid" : "password-valid";
			this.passwordUpperCaseClass = !this.password.match(/[A-Z]/g) ? "password-invalid" : "password-valid";
			this.passwordNumberClass = !this.password.match(/[0-9]/g) ? "password-invalid" : "password-valid";
			this.passwordSpecialCaseClass = !this.password.match(/(?=(.*[!"#$%&'()*+,./:;<=>?@\^_`{|}~\-]){2,})/g) ? "password-invalid" : "password-valid";
			this.passwordNonrepeatingClass = !this.password.match(/^(?!.*([\da-zA-Z!"#$%&'()*+,./:;<=>?@\^_`{|}~\-])\1{2,}).+$/g) ? "password-invalid" : "password-valid";
			this.passwordNonconsecutiveClass = hasConsecutiveCharacters(this.password) ? "password-invalid" : "password-valid";
			this.passwordLengthClass = this.password.length < 8 ? "password-invalid" : "password-valid";
		} else
			this.passwordNormalLengthClass = this.password.length < 8 ? "password-invalid" : "password-valid";

		if (this.enforcePasswordPolicy)
			this.passwordIsValid = isValidPasswordOption(this.password);
		else
			this.passwordIsValid = this.password.length >= 8;

		const strength = passwordStrength(this.password);
		if (this.passwordIsValid && strength > 50) {
			this.passwordStrengthClass = "password-strength-strong";
			this.passwordStrengthText = "Strong";
		} else if (strength > 50) {
			this.passwordStrengthClass = "password-strength-medium";
			this.passwordStrengthText = "Medium";
		} else {
			this.passwordStrengthClass = "password-strength-weak";
			this.passwordStrengthText = "Weak";
		}
	}

	validateConfirm() {
		this.passwordMatchClass = this.passwordMatch ? "password-match-positive" : "password-match-negative";
		this.passwordMatchText = this.passwordMatch ? "Match" : "No Match";
	}

	onCurrrentBlur() {
		const currentLoginSuccess = (message: string) => {
			logInfo('Current Password successfully verified');
			this.passwordCurrentError = "Password verified";
			this.currentPasswordErrorClass = "password-valid";
			this.currentPasswordIsValid = true;
		};
		const currentLoginFail = (reason: string) => {
			logInfo('Error verifying current password');
			this.passwordCurrentError = "Incorrect password";
			this.currentPasswordErrorClass = "password-invalid-error";
			this.currentPasswordIsValid = false;
		};
		checkPassword(this.identity, this.currentPassword, currentLoginSuccess, currentLoginFail);
	}

	onPasswordFocus() {
		this.editingPassword = true;
		this.passwordMatchClass = '';
		this.passwordMatchText = '';
		if (this.passwordInvalidError) this.passwordInvalidError = '';
	}

	onPasswordConfirmFocus() {
		this.editingConfirm = true;
		this.validateConfirm();
	}

	handlePasswordShowHide() {
		if (this.passwordExpired) {
			if (!this.currentPasswordIsValid)
				return;
			else
				this.passwordInputType = this.passwordInputType === 'password' ? 'text' : 'password';
		} else
			this.passwordInputType = this.passwordInputType === 'password' ? 'text' : 'password';
	}

	passwordShowHideClass() {
		if (this.passwordExpired) {
			if (this.currentPasswordIsValid) {
				if (this.passwordInputType === 'text')
					return 'icons-tool-show-and-hide-hide';
				if (this.passwordInputType === 'password')
					return 'icons-tool-show-and-hide-show-active';
			}
			return 'icons-tool-show-and-hide-show-inactive';
		} else {
			if (this.passwordInputType === 'text')
				return 'icons-tool-show-and-hide-hide';
			if (this.passwordInputType === 'password')
				return 'icons-tool-show-and-hide-show-active';
		}
	}

	handleConfirmShowHide() {
		this.confirmInputType = this.confirmInputType === 'password' ? 'text' : 'password';
	}

	confirmShowHideClass() {
		return this.passwordIsValid && this.confirmInputType === 'text' ? 'icons-tool-show-and-hide-hide' : 'icons-tool-show-and-hide-show-active';
	}

	navigateHome() {
		window.location.hash = "";
		// globals.pageReload();
	}
}
