<script setup lang="ts">
import type { PrimitiveProps } from "reka-ui"
import type { Component, HTMLAttributes } from "vue"
import type { ButtonVariants } from "."
import { LoaderIcon } from "@lucide/vue"
import { Primitive } from "reka-ui"
import { cn } from "@/lib/utils"
import { buttonVariants } from "."

interface Props extends PrimitiveProps {
  variant?: ButtonVariants["variant"]
  size?: ButtonVariants["size"]
  class?: HTMLAttributes["class"]
  disabled?: boolean
  /** Leading icon; a spinner takes its place while loading. */
  icon?: Component
  /** Busy: disabled, with a spinner in place of the icon (or before the label). */
  loading?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  as: "button",
})
</script>

<template>
  <Primitive
    data-slot="button"
    :data-variant="variant"
    :data-size="size"
    :data-loading="loading || undefined"
    :aria-busy="loading || undefined"
    :disabled="disabled || loading || undefined"
    :as="as"
    :as-child="asChild"
    :class="cn(buttonVariants({ variant, size }), props.class)"
  >
    <!-- With as-child the slot is the element itself, so there is no room for an icon. -->
    <template v-if="!asChild">
      <LoaderIcon v-if="loading" class="animate-spin" />
      <component :is="icon" v-else-if="icon" />
    </template>
    <slot />
  </Primitive>
</template>
