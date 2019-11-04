import { requestResetPassword } from '../../../auth/auth-utils';
import { tt } from 'lib/base/translate';
import { Modal, Button } from 'lib/components';
import { Component, Prop } from 'vue-property-decorator';
import Vue from 'vue';
import { escapeHTML } from 'lib/base/utils';
import template from './reset-password-request.vue';

interface IMessage {
	text?: string;
	type?: string;
}

@Component({
	components: {
		'app-modal': Modal,
		'app-button': Button
	},
	watch: {
		// Set focus on email input field
		active(newValue) { if (newValue) this.$nextTick(() => this.$refs.email.focus()); }
	},
	mixins: [template]
})
export default class ResetPasswordRequest extends Vue {
	name: 'ResetPasswordRequest';

	@Prop(Boolean) active: boolean;
	@Prop(String) email: string;

	message: IMessage = {};
	resetButtonDisabled: boolean = false;
	resetInputVisable: boolean = true;
	tt: (english?: string, ...args: Array<string | number>) => string = tt;

	get messageStyle() {
		if (this.message.type === 'error') {
			return { color: '#cc0000' };
		} else if (this.message.type === 'busy') {
			return { color: 'lightgray' };
		}
	}

	close() {
		this.$emit('close');
	}

	cancel() {
		this.$emit('hide');
		this.message = {};
		this.resetButtonDisabled = false;
		this.resetInputVisable = true;
	}

	reset() {
		this.resetButtonDisabled = true;
		this.message.type = 'busy';

		const success = (res, stats) => {
			this.resetInputVisable = false;
			this.message = {
				text: tt('An e-mail with instructions on how to reset your password has been sent to: ' + escapeHTML(this.email)),
				type: 'success'
			};
		};
		const fail = (request: XMLHttpRequest) => {
			setTimeout(() => {
				this.resetButtonDisabled = false;
				this.message = {
					text: tt("Password reset failed: " + request.responseText + "."),
					type: 'error'
				};
			}, 300);
		};
		requestResetPassword(this.email, success, fail);
	}
}
