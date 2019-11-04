<template>
  <div class="password-page-container">
    <div class="imqs-background" />
    <div class="imqs-background-overlay" />

    <app-reset-request :active="showResetPasswordRequest" @hide="showResetPasswordRequest = false"></app-reset-request>

    <div class="password-frame">
      <div class="password-logo-top">
        <div class="imqs-logo"></div>
      </div>

      <form id="password-form">
        <div id="password-confirm-expired" v-if="tokenExpired">
          <div class="password-flex-item">{{tt("Password reset link expired") }}</div>

          <div class="password-flex-item">
            <app-button
              id="reset-password-request"
              @click="showResetPasswordRequest = true"
              style="width: 62%; margin-top: 30px"
              type="button"
              colour="primary"
              :label="tt('Request new link')"
            ></app-button>
          </div>

          <div class="password-flex-item">
            <div id="password-back-to-login" @click="navigateHome()">{{tt("Back to login page")}}</div>
          </div>
        </div>
        <div v-else>
          <div class="password-header">
            <h5 class="password-welcome">{{tt(welcome)}}</h5>
            <p class="password-identity">{{tt(identity)}}</p>
          </div>

          <div v-if="passwordExpired">
            <div class="password-label">{{tt("Current Password")}}</div>
            <div style="width: 100%">
              <div class="password-textbox-div" style="width: 82%">
                <input
                  :type="currentInputType"
                  v-model="currentPassword"
                  @blur="onCurrrentBlur"
                  class="password-textbox-input"
                />

                <div class="password-textbox-show-hide-div">
                  <div
                    @click="currentInputType = currentInputType === 'password'? 'text': 'password'"
                    class="password-textbox-show-hide"
                    :class="currentInputType === 'password'? 'icons-tool-show-and-hide-show-active': 'icons-tool-show-and-hide-hide'"
                  ></div>
                </div>
              </div>
            </div>

            <div v-if="passwordCurrentError">
              <span :class="currentPasswordErrorClass">{{tt(passwordCurrentError)}}</span>
            </div>
          </div>

          <div class="password-flex-item">
            <div class="password-label">{{tt("New Password")}}</div>
            <div style="width: 100%">
              <div class="password-textbox-div" style="width: 82%">
                <input
                  :type="passwordInputType"
                  v-model="password"
                  @focus="onPasswordFocus"
                  @blur="editingPassword = false"
                  @keyup="validatePassword"
                  class="password-textbox-input"
                  :disabled="passwordExpired && !currentPasswordIsValid"
                />

                <div class="password-textbox-show-hide-div">
                  <div
                    @click="handlePasswordShowHide"
                    class="password-textbox-show-hide"
                    :class="passwordShowHideClass()"
                  ></div>
                </div>
              </div>

              <div
                class="password-side-message"
                :class="passwordStrengthClass"
              >{{tt(passwordStrengthText)}}</div>
            </div>
          </div>

          <div v-if="passwordInvalidError">
            <span class="password-invalid-error">{{tt(passwordInvalidError)}}</span>
          </div>

          <div>
            <div v-if="enforcePasswordPolicy">
              <div>
                <span
                  :class="passwordLowerCaseClass"
                >{{ tt("At least one lower case character (a-z)") }}</span>
              </div>
              <div>
                <span
                  :class="passwordUpperCaseClass"
                >{{ tt("At least one upper case character (A-Z)") }}</span>
              </div>
              <div>
                <span :class="passwordNumberClass">{{ tt("At least one number (0-9)") }}</span>
              </div>
              <div>
                <span
                  :class="passwordSpecialCaseClass"
                >{{ tt("At least two special character (!@#$%^&*)") }}</span>
              </div>
              <div>
                <span
                  :class="passwordNonrepeatingClass"
                >{{ tt("No more than two repeated characters") }}</span>
              </div>
              <div>
                <span
                  :class="passwordNonconsecutiveClass"
                >{{ tt("No more than two characters in a sequence") }}</span>
              </div>
              <div>
                <span :class="passwordLengthClass">{{ tt("At least 8 characters") }}</span>
              </div>
            </div>
            <div v-else>
              <div>
                <span :class="passwordNormalLengthClass">{{ tt("At least 8 characters") }}</span>
              </div>
            </div>
          </div>

          <div class="password-flex-item">
            <div class="password-label">{{tt("Confirm Password")}}</div>

            <div style="width: 100%">
              <div class="password-textbox-div" style="width: 82%">
                <input
                  :type="confirmInputType"
                  v-model="passwordConfirm"
                  @focus="onPasswordConfirmFocus"
                  @blur="editingConfirm = false"
                  @keyup="validateConfirm"
                  class="password-textbox-input"
                />

                <div class="password-textbox-show-hide-div">
                  <div
                    @click="handleConfirmShowHide"
                    class="password-textbox-show-hide"
                    :class="confirmShowHideClass()"
                  ></div>
                </div>
              </div>
              <div
                class="password-side-message"
                :class="passwordMatchClass"
              >{{tt(passwordMatchText)}}</div>
            </div>
          </div>

          <div class="password-submit">
            <app-button
              id="reset-password-ok"
              style="float: left; margin-left: 0"
              @click="submitPassword"
              type="button"
              colour="primary"
              :label="tt('OK')"
              :disabled="!(passwordIsValid && (password === passwordConfirm))"
            ></app-button>

            <div v-if="loggingIn" class="login-loader"></div>
          </div>
        </div>
      </form>
    </div>
  </div>
</template>
