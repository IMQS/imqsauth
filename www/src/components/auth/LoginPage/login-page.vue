<template>
  <div class="login-page-container">
    <div class="imqs-background" />
    <div class="imqs-background-overlay" />
    <a class="imqs-address" href="https://www.imqs.co.za/" target="_blank" />
    <app-reset-request
      :active="showResetPasswordRequest"
      :email="email"
      @hide="showResetPasswordRequest = false"
    ></app-reset-request>
    <div class="login-frame">
      <div class="login-logo-top">
        <div class="imqs-logo"></div>
      </div>
      <form id="login-form" autocomplete="on">
        <div>
          <div class="login-input-header">{{tt("Username")}}:</div>
          <div style="padding-right: 7px">
            <input
              v-model="email"
              id="login-email"
              autofocus
              name="email"
              v-bind:class="{ 'input-error-underline': usernameError }"
            />
          </div>
          <div id="username-error" class="login-error">
            <div v-if="usernameError">{{errorReason}}</div>
          </div>
          <div class="login-input-header">{{tt("Password")}}:</div>
          <div>
            <div class="password-textbox-div">
              <input
                :type="passwordDisplayType"
                v-model="password"
                @keyup.enter="login"
                v-bind:class="{ 'input-error-underline': passwordError }"
                class="password-textbox-input"
              />

              <div class="password-textbox-show-hide-div">
                <div
                  @click="passwordDisplayType = passwordDisplayType === 'password'? 'text': 'password'"
                  class="password-textbox-show-hide"
                  :class="passwordDisplayType === 'password'? 'icons-tool-show-and-hide-show-active': 'icons-tool-show-and-hide-hide'"
                ></div>
              </div>
            </div>
          </div>
          <div id="password-error" class="login-error">
            <div v-if="errorReason && !usernameError ">{{errorReason}}</div>
          </div>
          <div style="padding-top: 20px;">
            <app-button
              @click="login"
              type="button"
              colour="primary"
              :label="tt('Login')"
              :disabled="loggingIn"
            ></app-button>
            <div class="login-password-forget">
              <a
                @click="showResetPasswordRequest = true"
                id="login-password-forget"
                v-bind:class="{ 'disabled': loggingIn }"
              >{{tt("Forgot your password?")}}</a>
            </div>
            <div v-if="loggingIn" class="login-loader"></div>
          </div>
        </div>
      </form>
    </div>
  </div>
</template>
