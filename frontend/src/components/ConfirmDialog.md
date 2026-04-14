# ConfirmDialog.vue — Vue 3 Crash Course

This walkthrough dissects `ConfirmDialog.vue` feature by feature.  
Each snippet is taken directly from the file with annotations added.

---

## 1. Single-File Component (SFC) structure

Every `.vue` file is a **Single-File Component**. It has up to three top-level blocks:

```
┌─────────────────────┐
│  <template>         │  ← HTML / DOM structure
│  <script setup>     │  ← Component logic (TypeScript)
│  <style scoped>     │  ← CSS that only applies to THIS component
└─────────────────────┘
```

Vue 2 used `export default { ... }` inside `<script>`.  
Vue 3 adds the `setup` attribute (Composition API) — covered in section 4.

---

## 2. `<template>` — the HTML block

```vue
<template>
  <!-- Inline confirmation dialog -->
  <Teleport to="body">                          <!-- ① -->
    <div v-if="visible" ...>                    <!-- ② -->
      <div class="modal-box">
        <p :id="titleId" class="modal-title">   <!-- ③ -->
          {{ title }}                           <!-- ④ -->
        </p>
        <p v-if="message" class="modal-message">
          {{ message }}
        </p>
        <div class="modal-actions">
          <button class="btn-neutral"
                  @click="cancel">             <!-- ⑤ -->
            {{ cancelLabel }}
          </button>
          <button :class="'btn-' + variant"    <!-- ⑥ -->
                  @click="confirm">
            {{ confirmLabel }}
          </button>
        </div>
      </div>
    </div>
  </Teleport>
</template>
```

### ① `<Teleport to="body">`
A **built-in Vue 3 component** that physically moves its rendered output to a
different place in the real DOM (here: directly under `<body>`), while keeping
it logically owned by this component.

**Why?** Modals need to escape any parent that has `overflow: hidden` or a
`position: relative` stacking context — both of which would clip or break a
full-screen overlay.

> Vue 2 equivalent: the third-party `vue-portal` library, or manually
> appending elements with JavaScript.

### ② `v-if="visible"` — conditional rendering
A **directive** (always prefixed `v-`). The element and all its children are
**added to / removed from the DOM** based on the truthiness of `visible`.

```vue
<div v-if="visible">...</div>   <!-- rendered only when visible === true -->
```

> `v-show` is the alternative — it keeps the element in the DOM but toggles
> `display: none`. Use `v-show` for things that toggle frequently; `v-if` for
> things that are rarely shown.

Vue 2 and Vue 3 both support `v-if` identically.

### ③ `:id="titleId"` — attribute binding (shorthand for `v-bind:`)
The `:` prefix means "evaluate this as a JavaScript expression and bind the
result as the attribute value".

```vue
:id="titleId"        <!-- dynamic — titleId is a reactive variable -->
 id="titleId"        <!-- static  — literally the string "titleId" -->
```

### ④ `{{ title }}` — text interpolation (Mustache syntax)
Renders the value of `title` as plain text inside the element.
Reactive: updates automatically when `title` changes.

### ⑤ `@click="cancel"` — event listener (shorthand for `v-on:click`)
Calls the `cancel` function when the button is clicked.

```vue
@click="cancel"            <!-- call cancel() on click -->
@click="count++"           <!-- inline expression also works -->
@click.prevent="submit"    <!-- .prevent modifier calls event.preventDefault() -->
```

### ⑥ `:class="'btn-' + variant"` — dynamic class binding
Evaluates the expression and sets it as the `class` attribute.

```vue
:class="'btn-' + variant"          <!-- string expression -->
:class="{ active: isActive }"      <!-- object syntax: adds 'active' if isActive -->
:class="[base, extra]"             <!-- array syntax: merges multiple classes -->
```

---

## 3. `defineProps` — receiving data from a parent

```vue
<script setup lang="ts">
import { computed } from 'vue';

// ⑦ withDefaults + defineProps
const props = withDefaults(defineProps<{
  visible: boolean;        // required (no ?)
  title: string;           // required
  message?: string;        // optional  (the ? means it may be undefined)
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'primary' | 'danger';   // union type — only these two string values allowed
}>(), {
  confirmLabel: 'OK',      // default value when caller does not supply it
  cancelLabel:  'Cancel',
  variant:      'primary',
});
```

### ⑦ `defineProps` / `withDefaults`
`defineProps` is a **compiler macro** — you don't import it; Vue's compiler
recognises it and generates the correct runtime code.

The generic `<{ ... }>` is TypeScript's way of passing a type to a generic
function. Vue uses it to type-check props at compile time.

`withDefaults` wraps `defineProps` and lets you declare default values
separately from the type definition.

**Vue 2 equivalent:**
```js
export default {
  props: {
    visible:      { type: Boolean, required: true },
    title:        { type: String,  required: true },
    confirmLabel: { type: String,  default: 'OK' },
    variant:      { type: String,  default: 'primary' },
  }
}
```

---

## 4. `<script setup>` — Vue 3 Composition API

```vue
<script setup lang="ts">
```

The `setup` attribute on `<script>` is **Vue 3 only**. It is syntactic sugar
for the Composition API `setup()` function. Everything declared at the top
level of the block is automatically available in the template — no need to
`return` anything.

`lang="ts"` tells the compiler to treat the script as TypeScript.

**Vue 2** used the Options API:
```js
// Vue 2 style
export default {
  data()    { return { ... } },   // reactive state
  computed: { ... },              // derived values
  methods:  { ... },              // functions
  props:    { ... },
}
```

**Vue 3 Composition API** (without `setup` shorthand):
```js
export default {
  setup(props, ctx) {
    const titleId = computed(() => ...)
    function confirm() { ctx.emit('confirm') }
    return { titleId, confirm }   // must be returned to be usable in template
  }
}
```

**Vue 3 `<script setup>`** (what this file uses — most concise):
```vue
<script setup lang="ts">
const titleId = computed(() => ...)   // automatically available in template
function confirm() { emit('confirm') }
</script>
```

---

## 5. `computed` — derived reactive values

```vue
// ⑧ computed
const titleId = computed(() =>
  'confirm-dialog-title-' + Math.random().toString(36).slice(2)
);
```

### ⑧ `computed()`
Imported from `'vue'`. Creates a **read-only reactive reference** whose value
is derived from other reactive data. Vue caches the result and only
re-evaluates when its reactive dependencies change.

Access the value in script with `.value`; in templates Vue unwraps it
automatically:

```ts
console.log(titleId.value)   // in script
// {{ titleId }}              // in template — .value not needed
```

> In Vue 2 this was the `computed: { ... }` Options API section.

---

## 6. `defineEmits` — sending events to a parent

```vue
// ⑨ defineEmits
const emit = defineEmits<{
  (e: 'confirm'): void;
  (e: 'cancel'): void;
}>();

function confirm() { emit('confirm'); }
function cancel()  { emit('cancel'); }
```

### ⑨ `defineEmits`
Another compiler macro. Declares which custom events this component can fire.
The TypeScript generic defines the event names and their payload types.

The parent listens with `@confirm="..."` or `@cancel="..."`:

```vue
<!-- Parent usage -->
<ConfirmDialog
  :visible="showDialog"
  title="Are you sure?"
  @confirm="doDelete"
  @cancel="showDialog = false"
/>
```

**Vue 2 equivalent:**
```js
this.$emit('confirm')
// parent: <ConfirmDialog @confirm="doDelete" />
```

---

## 7. `<style scoped>` — component-scoped CSS

```vue
<style scoped>
.modal-overlay {
  position: fixed; inset: 0; z-index: 9999;
  background: rgba(0,0,0,.35);
  display: flex; align-items: center; justify-content: center;
}
/* ... */
</style>
```

The `scoped` attribute makes Vue add a unique data attribute (e.g.
`data-v-3a8f2c`) to every element in this component's template, and
automatically scope every CSS rule to match only elements with that attribute.

Result: `.modal-overlay` here will **never** clash with a `.modal-overlay`
class in any other component.

> Vue 2 supported `scoped` styles identically.

---

## 8. How a parent uses this component

```vue
<!-- AnyParent.vue -->
<script setup lang="ts">
import { ref } from 'vue';
import ConfirmDialog from './ConfirmDialog.vue';

const showConfirm = ref(false);   // ⑩ ref — a simple reactive value

function askConfirm() { showConfirm.value = true; }
function onConfirm()  { /* do the thing */; showConfirm.value = false; }
function onCancel()   { showConfirm.value = false; }
</script>

<template>
  <button @click="askConfirm">Delete</button>

  <ConfirmDialog
    :visible="showConfirm"
    title="Delete item?"
    message="This cannot be undone."
    variant="danger"
    confirm-label="Delete"
    @confirm="onConfirm"
    @cancel="onCancel"
  />
</template>
```

### ⑩ `ref()`
Creates a **reactive primitive** (string, number, boolean, etc.).
Must be accessed via `.value` in script; templates unwrap automatically.

```ts
const count = ref(0);
count.value++;          // in script
// {{ count }}          // in template
```

For objects/arrays use `reactive()` instead (no `.value` needed):
```ts
const state = reactive({ name: '', age: 0 });
state.name = 'Alice';   // direct mutation, no .value
```

---

## Quick reference cheat-sheet

| Syntax | Meaning | Vue 2? |
|---|---|---|
| `v-if="x"` | render element only if `x` is truthy | ✅ |
| `v-show="x"` | toggle `display:none` | ✅ |
| `v-for="item in list"` | loop | ✅ |
| `:prop="expr"` | bind attribute/prop to expression | ✅ |
| `@event="fn"` | listen for DOM or component event | ✅ |
| `{{ expr }}` | text interpolation | ✅ |
| `<Teleport to="...">` | render content elsewhere in DOM | ❌ Vue 3 only |
| `<script setup>` | Composition API shorthand | ❌ Vue 3 only |
| `defineProps<{...}>()` | typed props (compiler macro) | ❌ Vue 3 only |
| `defineEmits<{...}>()` | typed emits (compiler macro) | ❌ Vue 3 only |
| `computed(() => ...)` | derived reactive value | ✅ (as option) |
| `ref(value)` | reactive primitive | ❌ Vue 3 only |
| `reactive({...})` | reactive object | ❌ Vue 3 only |
| `<style scoped>` | component-scoped CSS | ✅ |

