<template>
  <app-modal :show="active" :clickAwayCloses="true" :escapeKeyCloses="true" @close="cancel">
    <div id="login-reset-password-dialog" slot="content" style="padding: 20px 20px 57px 20px;">
      <div
        v-if="resetInputVisable"
        style="text-align: justify; padding-bottom: 20px; font-size: 14px;"
      >{{ tt("Enter the email address of your account:") }}</div>
      <div>
        <input
          v-if="resetInputVisable"
          id="login-username-to-reset"
          ref="email"
          v-model="email"
          @keyup.enter="reset"
          class="g-textbox"
          style="width:100%; padding:6px; margin-bottom: 20px; font-size: 13px; box-sizing: border-box"
        />
        <div
          v-if="message.text"
          :style="messageStyle"
          style="padding-bottom: 20px; height: 18px; font-size: 15px;"
        >{{message.text}}</div>
      </div>
      <div>
        <app-button colour="neutral" :label="tt('Close')" @click="cancel" style="float: right;"></app-button>
        <app-button
          v-if="resetInputVisable"
          colour="primary"
          :label="tt('Reset')"
          :disabled="resetButtonDisabled"
          @click="reset"
          style="float: right;"
        ></app-button>
      </div>
    </div>
  </app-modal>
</template>
