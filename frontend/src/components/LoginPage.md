# LoginPage.vue — Vue 3 Crash Course (continued)

This walkthrough dissects `LoginPage.vue` feature by feature.
It builds on the concepts in `ConfirmDialog.md` and introduces:
`v-model`, `v-for`, `onMounted`, `async/await`, `computed`, `import type`,
and cross-component communication via `emit`.

---

## 1. What this component does

`LoginPage.vue` renders a login card that:
1. Collects a username/email + password via a form.
2. Calls `doLogin()` (from a shared *composable*) on submit.
3. On success, either redirects the browser to a `?redirect=` URL, or emits
   `'logged-in'` so the parent (`App.vue`) can switch views.
4. On failure, shows an error message.
5. Optionally shows OAuth provider buttons fetched from the API on mount.

---

## 2. Imports

```vue
<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';   // ① named imports from Vue

import { doLogin }            from '../composables/useSession';  // ② composable
import { getOAuthProviders }  from '../services/api';            // ③ API service
import type { OAuthProvider } from '../services/types';          // ④ type-only import
```

### ① Named imports from `'vue'`
Only the functions you actually use need to be imported.
`ref` and `computed` were covered in `ConfirmDialog.md`; `onMounted` is new —
see section 6.

### ② Composable — `useSession.ts`
A **composable** is a plain TypeScript module that uses Vue's reactivity APIs
to encapsulate reusable stateful logic. By convention they are named `use…`
and live in a `composables/` folder.

`useSession.ts` holds the global auth state in a **module-level** `reactive()`
object, so it is shared across every component that imports it — like a
lightweight store, no Vuex / Pinia needed for small apps.

```ts
// useSession.ts (simplified)
const state = reactive<SessionState>({ loggedIn: false, ... });

export async function doLogin(identity, password) {
  const data = await api.login(identity, password);
  state.loggedIn = true;
}
export const session = readonly(state);  // expose a read-only view
```

Because `state` is at **module scope**, it survives component mount/unmount
cycles and is the same object for every importer.

### ③ API service
A plain module (`services/api.ts`) that wraps `fetch()` calls.
Keeping network logic out of components makes both easier to test.

### ④ `import type`
TypeScript-only syntax. Tells the compiler and bundler that `OAuthProvider`
is used *only* as a type annotation — it generates **zero runtime JavaScript**.
Good habit: documents intent and can improve tree-shaking.

---

## 3. `defineEmits` — one event, no payload

```ts
const emit = defineEmits<{ (e: 'logged-in'): void }>();
```

Fires a single event with no data. The parent listens with `@logged-in="..."`.
Note this event is only emitted in *one* code path — the other path does a
full-page redirect instead (section 10).

---

## 4. `ref()` — reactive local state

```ts
const identity       = ref('');             // plain string, starts empty
const password       = ref('');
const errorMsg       = ref('');
const oauthProviders = ref<OAuthProvider[]>([]);   // ① typed array ref
const loading        = ref(false);          // ② boolean flag
```

### ① Generic type parameter `ref<OAuthProvider[]>([])`
TypeScript can't infer the element type from an empty `[]`, so we pass it
explicitly using the angle-bracket generic syntax.

### ② Boolean loading flag
A very common pattern: set `loading.value = true` before an async operation
and `false` in `finally` so the UI always recovers even if the request throws.

---

## 5. `v-model` — two-way binding

```vue
<input
  id="identity"
  v-model="identity"    <!-- ① two-way bind to ref -->
  type="text"
  :disabled="loading"   <!-- ② one-way bind, disables input during request -->
  required
/>
```

### ① `v-model="identity"`
Syntactic sugar that combines a value binding and an input listener:

```vue
<!-- v-model="identity" expands to: -->
:value="identity"
@input="identity = $event.target.value"
```

Typing in the input updates `identity.value`, and setting `identity.value`
in code updates the input — bidirectional.

**Vue 2** also supported `v-model` on native inputs (same expansion).  
**Vue 3** makes `v-model` fully customisable on *components* via
`modelValue` / `update:modelValue`, and allows multiple `v-model`s on one
component (`v-model:title`, `v-model:body`).

### ② `:disabled="loading"`
Disables the input while the login request is in flight, preventing
double-submission. The `:` prefix means `loading` is evaluated as a JS
expression, not the literal string `"loading"`.

---

## 6. `onMounted` — lifecycle hook

```ts
onMounted(async () => {              // ① fires after DOM insertion
  try {
    oauthProviders.value = await getOAuthProviders();   // ② fetch on mount
  } catch { /* OAuth not configured — silently ignore */ }
});
```

### ① `onMounted(callback)`
Registers a function to run **after** Vue inserts this component's DOM into
the page. The right place to fetch initial data, access real DOM nodes, or
start timers. The callback can be `async`.

**Vue 2** equivalent — the `mounted()` option:
```js
export default {
  async mounted() {
    this.oauthProviders = await getOAuthProviders();
  }
}
```

Common lifecycle hooks:

| Hook | When it fires |
|---|---|
| `onMounted` | after DOM insertion ← most common for data fetching |
| `onBeforeMount` | just before DOM insertion |
| `onUpdated` | after a reactive re-render |
| `onUnmounted` | after component is destroyed — clean up timers/subscriptions |

### ② Replacing a `ref` array
```ts
oauthProviders.value = await getOAuthProviders();
```
Replacing `.value` entirely triggers Vue's reactivity, re-rendering the list.

---

## 7. `computed` — transforming a list

```ts
const oauthProvidersWithRedirect = computed(() =>
  oauthProviders.value.map(p => ({
    ...p,                          // ① object spread — copy all properties
    LoginURL: redirectTarget
      ? `${p.LoginURL}${p.LoginURL.includes('?') ? '&' : '?'}redirect=${encodeURIComponent(redirectTarget)}`
      : p.LoginURL,                // ② ternary — conditional value
  }))
);
```

### ① Object spread `...p`
Copies all properties of `p` into the new object literal, then `LoginURL`
is overridden. Idiomatic for creating a modified copy without mutating the source.

### ② `computed` returning an array
`computed` isn't just for scalar values — it can return any derived value,
including a transformed array. Vue caches the result and only re-runs the
function when `oauthProviders.value` or `redirectTarget` changes.

---

## 8. `v-for` — rendering a list

```vue
<div
  v-for="provider in oauthProvidersWithRedirect"
  :key="provider.Name"
  class="oauth-provider"
>
  <a :href="provider.LoginURL" class="btn-oauth">
    Sign in with {{ provider.Name }}
  </a>
</div>
```

| Part | Meaning |
|---|---|
| `provider` | loop variable, available inside the element and its children |
| `oauthProvidersWithRedirect` | the array to iterate (the computed above) |
| `:key="provider.Name"` | stable unique identity for Vue's virtual DOM diff |

**`:key` is critical.** Without it, Vue may reuse the wrong DOM node when the
list changes (items added, removed, reordered), causing subtle rendering bugs.
Always use a stable, unique value per item.

Also note the `v-if` guard just above the loop:
```vue
<div v-if="oauthProviders.length > 0" class="oauth-divider">
```
The divider is only rendered when there is at least one OAuth provider.
`v-if` on a container element is a clean way to hide entire sections
conditionally.

---

## 9. `@submit.prevent` — form event + modifier

```vue
<form @submit.prevent="handleSubmit" novalidate>
```

`.prevent` is a **Vue event modifier** — it automatically calls
`event.preventDefault()`, stopping the browser from doing a full-page POST.

Common modifiers:

| Modifier | Effect |
|---|---|
| `.prevent` | `event.preventDefault()` |
| `.stop` | `event.stopPropagation()` |
| `.once` | listener fires only the first time |
| `.self` | only fires if event target is the element itself |
| `.enter` | only fires on the Enter key (`@keydown.enter`) |

`novalidate` is a plain HTML attribute that disables the browser's built-in
validation pop-ups so Vue can handle errors itself (via `errorMsg`).

---

## 10. `async handleSubmit()` — the submit handler

```ts
async function handleSubmit() {
  if (!identity.value || !password.value) return;   // ① guard
  errorMsg.value = '';
  loading.value  = true;
  try {
    await doLogin(identity.value, password.value);   // ② await composable
    if (redirectTarget) {
      window.location.href = redirectTarget;          // ③ full-page redirect
    } else {
      emit('logged-in');                              // ④ tell parent
    }
  } catch (e: unknown) {                             // ⑤ typed catch
    errorMsg.value = e instanceof Error
      ? e.message
      : 'Login failed. Please try again.';
  } finally {
    loading.value = false;                           // ⑥ always reset
  }
}
```

### ① Guard clause
The button is already `:disabled` when inputs are empty, but this defensive
check ensures the function is safe to call from anywhere.

### ② `await` composable
`doLogin` is an `async` function exported from `useSession.ts`. `await`
suspends execution here until the Promise resolves or rejects.

### ③ Full-page redirect vs ④ emit — two success paths

| Path | When | What happens |
|---|---|---|
| `window.location.href = redirectTarget` | URL has `?redirect=` | Whole browser tab navigates to another app |
| `emit('logged-in')` | No redirect param | Parent Vue component reacts and switches view |

The redirect path is for when this login page is used by *another* application
(e.g. Apache proxying `/auth/`). The emit path is for the normal in-app flow.

### ⑤ `catch (e: unknown)` — typed catch
TypeScript 4+ makes caught values `unknown` by default (safer than `any`).
The `instanceof Error` check **narrows the type** before accessing `.message`.

### ⑥ `finally` block
Runs whether `try` succeeded or `catch` ran. Guarantees `loading` is always
reset to `false` — critical for preventing a permanently-disabled button.

---

## 11. Security: `safeRedirectTarget()`

```ts
function safeRedirectTarget(): string | null {
  const params = new URLSearchParams(window.location.search);
  const target = params.get('redirect') ?? params.get('returnUrl') ?? '';
  if (!target) return null;
  try {
    const url = new URL(target, window.location.origin);  // ①
    if (url.hostname !== window.location.hostname) {       // ②
      console.warn('[auth] Ignoring cross-host redirect:', target);
      return null;
    }
    return url.href;
  } catch {
    return null;                                           // ③
  }
}
```

Not Vue-specific, but worth understanding:

### ① `new URL(target, base)`
The second argument is a base URL. A relative path like `/dashboard` resolves
to an absolute URL against the base. An already-absolute URL ignores the base.

### ② Hostname check — open-redirect prevention
An **open redirect** vulnerability lets an attacker craft a login link like
`/auth/ui/?redirect=https://evil.com`. After a successful login, the user would
be silently forwarded there. Comparing *hostnames* (not full origins) blocks
redirects to any different host while allowing different ports on the same host
(e.g. dev server on port 2003 vs app on port 80).

### ③ Malformed URL swallowed safely
`new URL()` throws on an invalid string. The empty `catch {}` returns `null`
instead of crashing the component.

---

## 12. `v-if` / `v-else` — conditional button label

```vue
<button type="submit" class="btn-primary"
        :disabled="loading || !identity || !password">
  <span v-if="loading">Signing in…</span>   <!-- shown while awaiting -->
  <span v-else>Sign In</span>               <!-- shown normally -->
</button>
```

`v-else` must immediately follow a sibling element with `v-if` (or `v-else-if`).
Only one `<span>` exists in the DOM at any time — the other is completely removed.

The `:disabled` expression combines three conditions with `||`. Vue evaluates
this as plain JavaScript — any truthy combination disables the button.

---

## 13. CSS — the `::before` / `::after` divider trick

```css
.oauth-divider::before,
.oauth-divider::after {
  content: '';      /* required — without this the pseudo-element is not rendered */
  flex: 1;          /* take up all remaining space in the flex row */
  height: 1px;
  background: #e0e0e0;
}
```

This creates the horizontal lines either side of "or" entirely in CSS, with no
extra HTML elements. The container is `display: flex` so the two pseudo-elements
and the `<span>or</span>` sit side-by-side and the lines stretch to fill space.
`scoped` applies the Vue data-attribute automatically so these rules cannot
leak into other components.

---

## Quick reference — new concepts in this file

| Concept | Syntax | Vue 2? |
|---|---|---|
| Two-way binding | `v-model="ref"` | ✅ same for native inputs |
| List rendering | `v-for="x in list" :key="x.id"` | ✅ |
| Lifecycle hook | `onMounted(async () => { ... })` | ✅ as `mounted()` option |
| Form submit | `@submit.prevent="fn"` | ✅ |
| Event modifier | `.prevent` `.stop` `.once` | ✅ |
| Conditional siblings | `v-if` / `v-else` | ✅ |
| Type-only import | `import type { Foo }` | ❌ TypeScript 3.8+ only |
| Composable | `use…` fn with module-scope `reactive()` | ❌ Vue 3 pattern |
| Typed catch | `catch (e: unknown)` + `instanceof` | ❌ TypeScript 4+ |
| Full-page redirect | `window.location.href = url` | n/a (plain JS) |
| Open-redirect guard | hostname compare via `new URL()` | n/a (plain JS) |
| Two success paths | emit vs `window.location.href` | n/a (design pattern) |

