<script setup lang="ts">
/**
 * The template form's sections as a sticky list of links. The link of the section in view is
 * highlighted; a click scrolls to its card.
 */
const { t } = useI18n()

const active = ref<TemplateFormSection>(TEMPLATE_FORM_SECTIONS[0])
/** Below the sticky page header: a section is current once its card's top has passed this line. */
const OFFSET = 120

function update() {
  const atBottom = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4
  if (atBottom) {
    active.value = TEMPLATE_FORM_SECTIONS[TEMPLATE_FORM_SECTIONS.length - 1]!
    return
  }
  let current: TemplateFormSection = TEMPLATE_FORM_SECTIONS[0]
  for (const section of TEMPLATE_FORM_SECTIONS) {
    const top = document.getElementById(templateSectionId(section))?.getBoundingClientRect().top
    if (top !== undefined && top <= OFFSET) current = section
  }
  active.value = current
}

let frame = 0
const onScroll = () => {
  cancelAnimationFrame(frame)
  frame = requestAnimationFrame(update)
}
// Capture: the page may scroll inside a container rather than the window.
onMounted(() => {
  document.addEventListener('scroll', onScroll, { capture: true, passive: true })
  update()
})
onBeforeUnmount(() => {
  document.removeEventListener('scroll', onScroll, { capture: true })
  cancelAnimationFrame(frame)
})

function go(section: TemplateFormSection) {
  document.getElementById(templateSectionId(section))?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}
</script>

<template>
  <nav :aria-label="t('templates.form.sectionsLabel')">
    <ul class="sticky top-20 flex flex-col gap-0.5 text-sm">
      <li v-for="section in TEMPLATE_FORM_SECTIONS" :key="section">
        <a
          :href="`#${templateSectionId(section)}`"
          class="block border-l-2 py-1.5 pl-3 transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
          :class="active === section ? 'border-primary font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'"
          :aria-current="active === section ? 'location' : undefined"
          @click.prevent="go(section)"
        >
          {{ t(`templates.form.sections.${section}`) }}
        </a>
      </li>
    </ul>
  </nav>
</template>
